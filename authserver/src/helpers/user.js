import { prisma } from "../config/database";
import { logger  } from "../utils/logger";


export class Auth { 
       constructor (formData) { 
        this.formData = formData;
       } 
       async DoesUserExist() { 
        try {
            const user = await prisma.user.findUnique({
                where: { email : this.formData.email }, 
            });
            return user ? true : false ;
        } catch (error) {
            throw error;
        }
       } 
    
}