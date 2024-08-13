import { Router } from "express";
import { authMiddleware } from "../middleware";
import { SigninSchema, SignupSchema } from "../types";
import { prismaClient } from "../db";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config";

const router = Router();

router.post("/signup", async (req, res) => {
    const body = req.body;
    const parsedBody = SignupSchema.safeParse(body);
    if (!parsedBody.success) {
        return res.status(411).json({
            message: "Incorrect inputs"
        })
    }
    // check if user already exists
    const userExists = await prismaClient.user.findFirst({
        where: {
            email: parsedBody.data.email
        }
    });
    if (userExists) {
        return res.status(403).json({
            message: "User already exists"
        })
    }

    // signup the user
    await prismaClient.user.create({
        data: {
            email: parsedBody.data.email,
            password: parsedBody.data.password,     // hash the password then store
            name: parsedBody.data.name
        }
    })
    return res.json({
        message: "You are signed up"
    })
});

router.post("/signin", async (req, res) => {
    const body = req.body;
    const parsedBody = SigninSchema.safeParse(body);
    if (!parsedBody.success) {
        return res.status(411).json({
            message: "Incorrect inputs"
        })
    }
    // check if user creds are correct
    const user = await prismaClient.user.findFirst({
        where: {
            email: parsedBody.data.email,
            password: parsedBody.data.password
        }
    });
    if (!user) {
        return res.status(403).json({
            message: "Sorry incorrect credentials"
        })
    }
    // sign the jwt
    const token = jwt.sign({
        id: user.id
    }, JWT_SECRET);
    res.json({
        token: token,
    });
});

router.get("/", authMiddleware, async (req, res) => {
    //@ts-ignore
    const id = req.id;
    const user = await prismaClient.user.findFirst({
        where: {
            id
        },
        select: {
            name: true,
            email: true
        }
    });
    return res.json({
        user
    })
});

export const userRouter = router;