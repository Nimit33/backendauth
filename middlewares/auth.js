
// auth, isStudent,isAdmin

const jwt = require("jsonwebtoken");
require("dotenv").config();

exports.auth = (req, res, next) => {
    //ek ke baad ek middleware pass krna pdega
    try {
        //extract JWT token
        //PENDING : other ways to fetch token
        const token = req.body.token;
        //request ki body mein se token nikal liya

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Token Missing',
            });
        }

        //verify the token
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET);
            //token ko decode krdega
            console.log(payload);
            //why this ?
            req.user = payload;
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: 'token is invalid',
            });
        }
        next();
    }
    catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Something went wrong, while verifying the token',
        });
    }

}


exports.isStudent = (req, res, next) => {
    try {
        if (req.user.role !== "Student") {
            return res.status(401).json({
                success: false,
                message: 'THis is a protected route for students',
            });
        }
        next();
    }
    catch (error) {
        return res.status(500).json({
            success: false,
            message: 'User Role is not matching',
        })
    }
}

exports.isAdmin = (req, res, next) => {
    try {
        if (req.user.role !== "Admin") {
            return res.status(401).json({
                success: false,
                message: 'THis is a protected route for admin',
            });
        }
        next();
    }
    catch (error) {
        return res.status(500).json({
            success: false,
            message: 'User Role is not matching',
        })
    }
}