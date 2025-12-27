import { Router, Request, Response } from 'express';
import { authMiddleware } from '../AuthMiddleware.js';
import { metricMiddleware } from '../MetricMiddleware.js';
import pool from '../db/dbConnection.js';

const metrics = metricMiddleware({
    service: 'user-service',
    url:'https://szymonsamus.dev/api/metrics'
});

const router = Router();
router.use(metrics);
router.use(authMiddleware);

// Define your user-related routes here
router.put('/user/last-viewed', async (req: Request, res: Response): Promise<void> => {
    const userId = req.user?.id;
    const lastViewed = req.body.lastViewedTasks;
    if (!Array.isArray(lastViewed) || lastViewed.length > 10) {
        res.status(400).json({ error: 'Last viewed must be an array of up to 10 task IDs' });
        return;
    }
    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    try {
        const historyResult = await pool.query(
            'UPDATE users SET last_viewed_tasks = $1 WHERE id = $2 RETURNING last_viewed_tasks',
            [lastViewed, userId]
        );
        // console.log('Updated last viewed tasks:', historyResult.rows[0].last_viewed_tasks);
        res.status(200).json({
            lastViewedTasks: historyResult.rows[0].last_viewed_tasks});
    } catch (error) {
        console.error('Error fetching user history:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;
