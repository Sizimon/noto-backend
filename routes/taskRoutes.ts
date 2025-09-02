import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { authMiddleware } from '../AuthMiddleware.js';
import pool from '../db/dbConnection.js';

const generalLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.'
    }
});

const router = Router();
router.use(authMiddleware);
router.use(generalLimiter);

// Endpoint to create a new task (notepad, kanban, or list)
// This endpoint expects a JSON body with a "type" field indicating the type of task to create.
// The "type" can be 'note'.
router.post('/tasks', async (req: Request, res: Response): Promise<void> => {
    try {
        const type = req.body;
        console.log('Received task type:', type);

        const userId = req.user?.id;
        console.log('User ID from request:', userId);

        if (!userId) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }

        if (type.type === 'note') {
            const noteResult = await pool.query(
                'INSERT INTO notepads (title, content, user_id) VALUES ($1, $2, $3) RETURNING *',
                ['Untitled Note', '', userId]
            );
            res.status(201).json(noteResult.rows[0]);
        } else {
            res.status(400).json({ error: 'Invalid task type' });
            return;
        }
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// Endpoint to fetch all tasks for the authenticated user
// This endpoint will return all tasks (notepads) for the authenticated user, including their tags.

router.get('/tasks/fetch', async (req: Request, res: Response): Promise<void> => {
    const userId = req.user?.id;
    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    try {
        const notepadsResult = await pool.query(
            'SELECT *, \'note\' as type FROM notepads WHERE user_id = $1',
            [userId]
        );
        const notepads = notepadsResult.rows;
        const notepadIds = notepads.map(notepad => notepad.id);

        if (notepadIds.length > 0) {
            const tagsResult = await pool.query(
                `SELECT nt.notepad_id, t.id as id, t.title, t.color
                FROM notepad_tags nt
                JOIN tags t ON nt.tag_id = t.id
                WHERE nt.notepad_id = ANY($1::int[]) AND t.user_id = $2`,
                [notepadIds, userId]
            );

            type Tag = { id: Number | number, title: string, color: string };
            let tagsForNotepad: Record<string, Tag[]> = {};
            tagsResult.rows.forEach(row => {
                if (!tagsForNotepad[row.notepad_id]) {
                    tagsForNotepad[row.notepad_id] = [];
                }
                tagsForNotepad[row.notepad_id].push({
                    id: row.id,
                    title: row.title,
                    color: row.color
                });
            });

            const notepadsWithTags = notepads.map(notepad => ({
                ...notepad,
                tags: tagsForNotepad[notepad.id] || []
            }));

            res.status(200).json({
                notepads: notepadsWithTags,
            });
        }
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint to edit a task
// This endpoint expects a JSON body with fields to update.
// It will update the task in the notepads table and return the updated task.
// The task ID is passed as a URL parameter.
// It will only update fields that are present in the request body.
// If no valid fields are provided, it will return a 400 error.
router.put('/tasks/edit/:id', async (req: Request, res: Response): Promise<void> => {
    const taskId = req.params.id;
    const userId = req.user?.id;

    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    // Check the request body for valid fields to update
    const allowedFields = ['title', 'content', 'is_favorite'];

    // Store updates and values for the query
    const updates: string[] = [];
    const values: any[] = [];

    // Start parameter index at 1 for PostgreSQL
    // PostgreSQL uses $1, $2, etc. for parameterized queries
    let paramIndex = 1;

    // Iterate over allowed fields and check if they are present in the request body
    for (const field of allowedFields) {
        if (field in req.body) {
            updates.push(`${field} = $${paramIndex}`); // Push the string for the update
            values.push(req.body[field]); // Push the value to the values array
            paramIndex++;
        }
    }

    if (updates.length === 0) {
        res.status(400).json({ error: 'No valid fields to update' });
        return;
    }

    // Add taskId and userId to the values array
    values.push(taskId, userId);

    const query = `
        UPDATE notepads
        SET ${updates.join(', ')}
        WHERE id = $${paramIndex} AND user_id = $${paramIndex + 1}
        RETURNING *
    `;

    console.log('Executing query:', query);
    console.log('With values:', values);

    try {
        const result = await pool.query(query, values);
        if (result.rows.length === 0) {
            res.status(404).json({ error: 'Task not found' });
            return;
        }

        res.status(200).json(result.rows[0]);
    } catch (error) {
        console.error('Error updating task:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Endpoint to permanently delete a task
// This endpoint expects the task ID to be passed as a URL parameter.
// It will delete the task from the notepads table and any associated records in the notepad_tags table, due to the foreign key constraint.
router.delete('/tasks/delete/:id', async (req: Request, res: Response): Promise<void> => {
    const taskId = req.params.id;
    const userId = req.user?.id;
    const taskIdNumber = Number(taskId);

    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    try {
        const result = await pool.query(
            'DELETE FROM notepads WHERE id = $1 AND user_id = $2 RETURNING *',
            [taskIdNumber, userId]
        );

        if (result.rows.length === 0) {
            res.status(404).json({ error: 'Task not found' });
            return;
        }

        await pool.query( // Query to remove the deleted task from the user's last viewed tasks
            `UPDATE users 
            SET last_viewed_tasks = array_remove(last_viewed_tasks, $1)
            WHERE id = $2`,
            [taskIdNumber, userId]
        )

        res.status(200).json({ message: 'Task deleted successfully, last viewed tasks updated' });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint to fetch all tags for the authenticated user
// This endpoint will return all tags associated with the user, including their ID, title, and color.
// It will return an empty array if no tags are found.

router.get('/tags/fetch', async (req: Request, res: Response): Promise<void> => {
    const userId = req.user?.id;
    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    try {
        const tagsResult = await pool.query(
            'SELECT id, title, color FROM tags WHERE user_id = $1',
            [userId]
        );
        res.status(200).json(tagsResult.rows);
        console.log('Fetched tags:', tagsResult.rows);
    } catch (error) {
        console.error('Error fetching tags:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint to create a new tag and associate it with a task
// This endpoint expects a JSON body with "title" and "color" fields.
// It will insert a new tag into the tags table and create a record in the notepad_tags table to associate the tag with the task.
// If a tag with the same title and color already exists, it will update the existing tag instead of creating a new one.
// The task ID is passed as a URL parameter.
router.post('/tasks/:taskId/tags', async (req: Request, res: Response): Promise<void> => {
    const { title, color } = req.body;
    const taskId = req.params.taskId;
    const userId = req.user?.id;
    console.log('Adding tag:', { title, color }, 'to task ID:', taskId, 'for user ID:', userId);
    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    try {
        const tagResult = await pool.query(
            `INSERT INTO tags (title, color, user_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (title, color) DO UPDATE SET title = EXCLUDED.title
            RETURNING id, title, color`,
            [title, color, userId]
        );
        const tagId = tagResult.rows[0].id;
        console.log('Tag created or updated:', tagResult.rows[0]);

        const notepadTagsResult = await pool.query(
            'INSERT INTO notepad_tags (notepad_id, tag_id) VALUES ($1, $2) RETURNING *',
            [taskId, tagId]
        );
        console.log('Notepad tag correlation created:', notepadTagsResult.rows[0]);
        res.status(201).json({
            tag: tagResult.rows[0],
            notepad_tag: notepadTagsResult.rows[0]
        });
    } catch (error) {
        console.error('Error adding tag to task:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint to add an existing tag to a task
// This endpoint expects the tag ID to be passed as a URL parameter.
// It will insert a new record into the notepad_tags table to associate the tag with the task.
router.post('/tasks/:id/tags/existing/:tagId', async (req: Request, res: Response): Promise<void> => {
    const taskId = req.params.id;
    const tagId = req.params.tagId;
    const userId = req.user?.id;

    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    console.log('Adding existing tag ID:', tagId, 'to task ID:', taskId, 'for user ID:', userId);

    try {
        const result = await pool.query(`
            INSERT INTO notepad_tags (notepad_id, tag_id)
            VALUES ($1, $2)
            ON CONFLICT (notepad_id, tag_id) DO NOTHING
            RETURNING *
        `, [taskId, tagId]);

        if (result.rows.length === 0) {
            res.status(404).json({ error: 'Tag not found for this task' });
            return;
        }

        res.status(200).json({ message: 'Tag added to task successfully' });
    } catch (error) {
        console.error('Error adding existing tag to task:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint to remove a tag from a task
// This endpoint expects the task ID and tag ID to be passed as URL parameters.
// It will delete the corresponding record from the notepad_tags table.
router.delete('/tasks/:id/tags/:tagId', async (req: Request, res: Response): Promise<void> => {
    const taskId = req.params.id;
    const tagId = req.params.tagId;
    const userId = req.user?.id;

    console.log('Removing tag ID:', tagId, 'from task ID:', taskId, 'for user ID:', userId);

    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    try {
        const result = await pool.query(
            'DELETE FROM notepad_tags WHERE notepad_id = $1 AND tag_id = $2 RETURNING *',
            [taskId, tagId]
        );

        if (result.rowCount === 0) {
            res.status(404).json({ error: 'Tag not found for this task' });
            return;
        }

        res.status(200).json({ message: 'Tag removed from task successfully' });
    } catch (error) {
        console.error('Error removing tag from task:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint to permanently delete a tag
// This endpoint expects the tag ID to be passed as a URL parameter.
// It will delete the tag from the tags table and any associated records in the notepad_tags table, due to the foreign key constraint.
router.delete('/tags/:tagId', async (req: Request, res: Response): Promise<void> => {
    const tagId = req.params.tagId;
    const userId = req.user?.id;

    console.log('Deleting tag ID:', tagId, 'for user ID:', userId);

    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    try {
        const result = await pool.query(
            'DELETE FROM tags WHERE id = $1 AND user_id = $2 RETURNING *',
            [tagId, userId]
        );
        if (result.rowCount === 0) {
            res.status(404).json({ error: 'Tag not found' });
            return;
        }
        
        res.status(200).json({ message: 'Tag deleted successfully' });
    } catch (error) {
        console.error('Error deleting tag:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;
