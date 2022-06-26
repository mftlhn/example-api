<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|min:8'
            ]);

            if ($validator->fails()) {
                return ResponseFormatter::error(null, $validator->errors(), 404);
            }
            $insert = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);
            // $token = $insert->createToken('auth_token')->plainTextToken;

            return ResponseFormatter::success(null, 'User Registered');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Register Failed', 500);
        }

    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'required',
                'password' => 'required'
            ]);

            $credentials = request(['email', 'password']);
            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentication Failed', 500);
            }
            $user = User::where('email', $request->email)->first();
            if(!Hash::check($request->password, $user->password, [])) {
                throw new Exception('Invalid Credentials');
            }
            $tokenResult = $user->createToken('auth_token')->plainTextToken;

            return [
                'token' => $tokenResult,
                'data' => $user
            ];

        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        }
    }

    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'You have successfully logged out'
        ];
    }

    public function getData()
    {
        $user = User::find(Auth::user()->id);
        return ResponseFormatter::success($user, 'User successfully generated');
    }
}
