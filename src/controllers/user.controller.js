import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from "../utils/ApiError.js";
import { User } from '../models/user.model.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from 'jsonwebtoken';


const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });
        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token");
    }
};



const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exits: username ans email
    // check for images, check for avatar
    // upload them to cloudinary, avatar  
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res
    const { fullName, email, username, password } = req.body;
    console.log(fullName, email, username, password);
    if ([fullName, email, username, password].some((field) => field?.trim() === "")) {
        throw new ApiError(400, "All fields are required");
    }
    const existedUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existedUser) {
        throw new ApiError(409, 'User Already Exist');
    }
    console.log(existedUser);
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    if (!avatarLocalPath) {
        throw new ApiError(400, 'Avatar file is required');
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    console.log(req.files);
    if (!avatar) {
        throw new ApiError(400, 'Avatar file is required');
    }
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase(),

    });
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong when registering the user");
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User Registered Successfully")
    );

});

const loginUser = asyncHandler(async (req, res) => {
    // req body -> data
    // username or email
    // find the user
    // password check
    // access and refresh token
    // send cookie

    const { username, email, password } = req.body;
    if (!username && !email) {
        throw new ApiError(400, "username or email is required ");
    }
    const user = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (!user) {
        throw new ApiError(404, "User does not exist");
    }
    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(404, "Invalid user credential");
    }
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");
    const option = {
        httpOnly: true,
        secure: true,
    };
    return res
        .status(200)
        .cookie("accessToken", accessToken, option)
        .cookie("refreshToken", refreshToken, option)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken,
                },
                "User logged in successfully"
            )
        );
});

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, {
        $unset: {
            refreshToken: 1
        },

    },
        {
            new: true
        }
    );
    const option = {
        httpOnly: true,
        secure: true,
    };
    return res
        .status(200)
        .clearCookie('accessToken', option)
        .clearCookie('refreshToken', option)
        .json(new ApiResponse(200, {}, "User logout"));

});

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
        if (!incomingRefreshToken) {
            throw new ApiError(401, "Unauthorized request");
        }
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decodedToken?._id);
        if (!user) {
            throw new ApiError(401, "Invalid Refresh Token");
        }
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expire or used");
        }
        const option = {
            httpOnly: true,
            secure: true,
        };
        const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshTokens(user?._id);
        return res.status(200)
            .cookie('refreshToken', newRefreshToken, option)
            .cookie('accessToken', accessToken, option)
            .json(new ApiResponse(200, { accessToken, newRefreshToken }, "Access token refresh"));
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token");
    }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
    try {
        const { oldPassword, newPassword, confirmPassword } = req.body;
        if (!(newPassword === confirmPassword)) {
            throw new ApiError(400, "new password and confirm password doesn't match");
        }
        const id = req.user?._id;
        const user = await User.findById(id);
        const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
        if (!isPasswordCorrect) {
            throw new ApiError(400, 'Invalid old Password');
        }
        user.password = newPassword;
        await user.save({ validateBeforeSave: false });
        return res.status(201).json(new ApiResponse(201, {}, "password changed successfully"));
    } catch (error) {
        throw new ApiError(400, "Some thing wrong with change ");
    }
});

const getCurrentUser = asyncHandler(async (req, res) => {
    const currentUser = req.user;
    return res.status(200)
        .json(
            new ApiResponse(200, currentUser, "current user fetched successfully")
        );
});
const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullName, email, username } = req.body;
    if (fullName || email || username) {
        throw new ApiError(400, "All fields are required");
    }
    const id = req.user?._id;
    // const user = User.findById(id);
    // if (!user) {
    //     throw new ApiError(400, "user not found for update");
    // }
    const user = await User.findByIdAndUpdate(
        id,
        {
            $set: {
                fullName,
                email,
                username
            }
        },
        { new: true }
    ).select("-password");

    return res.status(200).json(new ApiResponse(200, user, "Account Details Successfully"));
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;
    if (!avatarLocalPath) {
        new ApiError(400, "Avatar File is missing");
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    if (!avatar.url) {
        new ApiError(400, "Error  while uploading on avatar");
    }
    const id = req.user?._id;
    const user = await User.findByIdAndUpdate(id, {
        $set: {
            avatar: avatar.url
        }
    },
        {
            new: true
        }
    ).select("-password");
    return res.status(200).json(new ApiResponse(200, user, "User Avatar Updated Successfully"));
});
const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;
    if (!coverImageLocalPath) {
        new ApiError(400, "cover image File is missing");
    }
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    if (!coverImage.url) {
        new ApiError(400, "Error  while uploading on cover image");
    }
    const id = req.user?._id;
    const user = await User.findByIdAndUpdate(id, {
        $set: {
            coverImage: coverImage.url
        }
    },
        {
            new: true
        }
    ).select("-password");
    return res.status(200).json(new ApiResponse(200, user, "User Cover Image Updated Successfully"));
});


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
};