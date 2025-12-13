import { Pool } from 'pg';
import pg from 'pg';
import dotenv from 'dotenv';
dotenv.config();
pg.types.setTypeParser(20, val => Number(val)); // PSQL sends Bigints as strings, this ensures it always converts bigints to actual numbers > 20 is the OID for BIGINT
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.NOTO_DB_HOST,
    database: process.env.NOTO_DB_NAME,
    password: process.env.NOTO_DB_PASSWORD,
    port: process.env.NOTO_DB_PORT ? Number(process.env.NOTO_DB_PORT) : 5432, // Default to 5432 if not set
});
export default pool;
