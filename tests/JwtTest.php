<?php
namespace jonlink\Jwt\Tests\Support;

use jonlink\Jwt\JwtPhp as Jwt;
use Orchestra\Testbench\TestCase as TestbenchTestCase;

class JwtTest extends TestbenchTestCase {
    // good JWT payload
    // {
    //     "sub": "1234567890",
    //     "name": "John Doe",
    //     "iat": 1516239022
    // }
    // bad JWT payload (signature is bad for invalid token)
    // {
    //     "sub": "1234567890",
    //     "name": "John Doe",
    //     "exp": 1516239022
    // }
    private const VALID_JWT   = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.H3e47aFn4-ES1GQQ2bFxFWkJYNuW2RmLXENBzqXXDOwu5XyVZQElhjVSzbhNvnfnEh0gqLNxYLXYtFPpO_YRQw';
    private const INVALID_JWT = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.H3e47aFn4-ES1GQQ2bFxFWkJYNuW2RmLXENBzqXXDOwu5XyVZQElhjVSzbhNvnfnEh0gqLNxYLXYtFPpO_YRQw';
    private const EXPIRED_JWT = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.A9VZhgivYCm2pfNpgh06NknetVrpF3w-60Dwuw41ea4td4qktOh7CV6TExb5hH2oR_osnvPbIONtcu643vnJqw';
    private const SECRET      = '123';

    public function testCanDecodePayload(): void {
        $jwt = new Jwt(
            token: self::VALID_JWT,
            secret: self::SECRET,
        );

        $this->assertEquals('{"sub":"1234567890","name":"John Doe","iat":1516239022}', json_encode($jwt->payload()));
    }

    public function testNoExpirationDoesNotExpire(): void {
        $jwt = new Jwt(
            token: self::VALID_JWT,
            secret: self::SECRET,
        );

        $this->assertFalse($jwt->isExpired());
    }

    public function testExpiredTokensAreExpired(): void {
        $jwt = new Jwt(
            token: self::EXPIRED_JWT,
            secret: self::SECRET,
        );

        $this->assertTrue($jwt->isExpired());
    }

    public function testValidTokensAreValid(): void {
        $jwt = new Jwt(
            token: self::VALID_JWT,
            secret: self::SECRET,
        );

        $this->assertTrue($jwt->isValid());
    }

    public function testInvalidTokensAreInvalid(): void {
        $jwt = new Jwt(
            token: self::INVALID_JWT,
            secret: self::SECRET,
        );

        $this->assertFalse($jwt->isValid());
    }
}
