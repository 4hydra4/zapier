"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.userRouter = void 0;
const express_1 = require("express");
const middleware_1 = require("../middleware");
const types_1 = require("../types");
const db_1 = require("../db");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const config_1 = require("../config");
const router = (0, express_1.Router)();
router.post("/signup", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const body = req.body;
    const parsedBody = types_1.SignupSchema.safeParse(body);
    if (!parsedBody.success) {
        return res.status(411).json({
            message: "Incorrect inputs"
        });
    }
    // check if user already exists
    const userExists = yield db_1.prismaClient.user.findFirst({
        where: {
            email: parsedBody.data.email
        }
    });
    if (userExists) {
        return res.status(403).json({
            message: "User already exists"
        });
    }
    // signup the user
    yield db_1.prismaClient.user.create({
        data: {
            email: parsedBody.data.email,
            password: parsedBody.data.password, // hash the password then store
            name: parsedBody.data.name
        }
    });
    return res.json({
        message: "You are signed up"
    });
}));
router.post("/signin", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const body = req.body;
    const parsedBody = types_1.SigninSchema.safeParse(body);
    if (!parsedBody.success) {
        return res.status(411).json({
            message: "Incorrect inputs"
        });
    }
    // check if user creds are correct
    const user = yield db_1.prismaClient.user.findFirst({
        where: {
            email: parsedBody.data.email,
            password: parsedBody.data.password
        }
    });
    if (!user) {
        return res.status(403).json({
            message: "Sorry incorrect credentials"
        });
    }
    // sign the jwt
    const token = jsonwebtoken_1.default.sign({
        id: user.id
    }, config_1.JWT_SECRET);
    res.json({
        token: token,
    });
}));
router.get("/", middleware_1.authMiddleware, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    //@ts-ignore
    const id = req.id;
    const user = yield db_1.prismaClient.user.findFirst({
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
    });
}));
exports.userRouter = router;
