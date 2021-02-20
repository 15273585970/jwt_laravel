<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class ApiController extends Controller
{
    public $loginAfterSignUp = true;

    public function register(Request $request)
    {
        $user = new User();
        $user->user_name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->original_password = $request->password;
        $user->save();

        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }

        return $this->success('','注册成功',[
            'success' => true,
            'data' => $user
        ]);
    }

    public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        $jwt_token = null;

        if (!$jwt_token = JWTAuth::attempt($input)) {
            return $this->error('','登陆异常：Invalid Email or Password');
        }

        return $this->success('','登陆成功',[
            'success' => true,
            'token' => $jwt_token,
        ]);
    }

    public function logout(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        try {
            JWTAuth::invalidate($request->token);
            return $this->success('','User logged out successfully');
        } catch (JWTException $exception) {
            return $this->error(500,'Sorry, the user cannot be logged out');
        }
    }

    public function getAuthUser(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        $user = JWTAuth::authenticate($request->token);

        return $this->success('','获取成功',['user' => $user]);
    }

    /**
     * 请求成功
     * @param int $status 请求状态码
     * @param string $msg 提示消息
     * @param string $content 返回内容
     * @return \Illuminate\Http\JsonResponse
     */
    public function success($status = 200, $msg = '请求成功', $content = '')
    {
        return response()->json(['status' => $status,'msg' => $msg, 'content' => $content]);
    }


    /**
     * 请求失败
     * @param int $status
     * @param string $msg
     * @param string $content
     * @return \Illuminate\Http\JsonResponse
     */
    public function error($status = 400, $msg = '请求失败', $content = '')
    {
        return response()->json(['status' => $status,'msg' => $msg, 'content' => $content]);
    }
}

