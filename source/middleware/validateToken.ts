import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const jwt_secret = process.env.JWT_SECRET || '';

export const validateToken = (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    jwt.verify(token, jwt_secret, (err, decoded) => {
        if (err) {
            console.log('Token verification error:', err);
            return res.status(401).json({ message: "Invalid token" });
        }

        (req as any).user = decoded;
        next();
    });
};

export default validateToken;