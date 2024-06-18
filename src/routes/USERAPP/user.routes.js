import { Router } from "express";
import { 
    getUser, 
    login, 
    register, 
} from "../../controllers/userapp/v1/auth.Controller.js";
import { auth } from "../../middlewares/auth.middlewares.js"
import { PLATFORM } from "../../constants.js"

const router = Router()

router.route("/register").post(register)
router.route("/login").post(login)
router.route("/me").get(auth(PLATFORM.USERAPP),getUser);

export default router