import { Request, Response, NextFunction } from 'express';

export function metricMiddleware({ service, url }: { service: string; url: string }) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const start = Date.now();

        res.on('finish', () => {
            fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    service,
                    method: req.method,
                    status: res.statusCode,
                    latencyMs: Date.now() - start
                })
            }).catch((err) => {
                console.error('Error sending metrics:', err);
            });
        });
        
            next();
        }
}