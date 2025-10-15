import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import userModel from '../models/userModel.js';

export const register  = async (req,res)=>{
    const {name,email,password} = req.body;

    if(!name || !email|| !password){
        return res.json({success:false,message:'Missing details'})
    }

    try{
        const existingUser = await User.findOne({email});

        if(existingUser){
            return res.json({success:false,message:"User already exists"});
        }

        const hashedPassword = await bcrypt.hash(password,10);

        const user = new User({name,email,password:hashedPassword});
        await user.save();

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV === 'production'? 'none' : 'strict',
            maxAge:7*24*60*60*1000
        });

        // Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Our Service',
            text: `welcome to the site. Your account has been created with email id: ${email}`
        };

        await transporter.sendMail(mailOptions);

        return res.json({success:true,message:"Registration successful"});

    }catch(error){
        
        return res.json({success:false,message:error.message})
    }

}

export const login = async (req,res)=>{
    const {email,password} = req.body;

    if(!email|| !password){
        return res.json({success:false,message:'Missing details'})
    }

    try{
        const user = await userModel.findOne({email});

        if(!user){
            return res.json({success:false,message:"Invalid email"})
        }

        const isMatch = await bcrypt.compare(password,user.password);

        if(!isMatch){
            return res.json({success:false,message:"Invalid password"})
        }
        
        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV === 'production'? 'none' : 'strict',
            maxAge:7*24*60*60*1000
        })

        return res.json({success:true,message:"Login successful"})

    }catch(error){
        return res.json({success:false,message:error.message})
    }
}

export const logout = (req,res)=>{
    try{
        res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV === 'production'? 'none' : 'strict',
        });

        return res.json({success:true,message:"Logged out"})
    }catch(error){
        return res.json({success:false,message:error.message})
    }
}


//send verificaiton opt to the users email
export const senVerifyOtp  = async(req,res)=>{
    try{
       const {userId} = req.body; 
       const user = await userModel.findById(userId);
        if(user.isAccountVerified){
            return res.json({success:false,message:"Account already verified"});
        }

        const otp = String(Math.floor(100000+ Math.random()*900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24*60*60*1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account verification otp',
            text: `Your account verification otp is: ${otp}.Verify this account using this otp.`
        }

        await transporter.sendMail(mailOptions);

        res.json({success:true,message:"Verification OTP sent on email"})

    }catch(error){
        res.json({success:false,message:error.message});
    }
} 

export const verifyEmail = async(req,res)=>{
    const {userId} = req.body;

    if(!userId || !otp){
        return res.json({success:false,message:'Missing details'});
    }
    try{
       const user = await userModel.findById(userId);

       if(!user){
        return  res.json({success:false,message:"User not found"});
       }

       if(user.verifyOtp===''|| user.verifyOtp !== otp){
        return  res.json({success:false,message:"Invalid OTP"});
       }

       if(user.verifyOtpExpireAt <Date.now()){
        return  res.json({success:false,message:"OTP Expired"});    
       }

       user.isAccountVerified = true;
       user.verifyOtp = '';
       user.verifyOtpExpireAt = 0;

       await user.save();
       return res.json({success:true,message:"Account verified successfully"});
       
    }catch(error){
        res.json({success:false,message:error.message});
    }
}