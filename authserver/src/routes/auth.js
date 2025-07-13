import express from "express"; 
import { login, register } from "../controllers/AuthController.js";
import { originValidator, strictOriginValidator } from "../middleware/originValidator.js";

const router = express.Router(); 


router.use('/auth/*', originValidator);

// Auth routes with origin validation
router.post('/auth/register', strictOriginValidator, register);
router.post('/auth/login', strictOriginValidator, login);

export const authRoutes = router; 
