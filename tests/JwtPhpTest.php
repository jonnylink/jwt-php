<?php
namespace jonlink\Jwt\Tests;

use jonlink\Jwt\JwtPhp as Jwt;
use PHPUnit\Framework\TestCase;

class JwtPhpTest extends TestCase {
    private const VALID_JWT             = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.H3e47aFn4-ES1GQQ2bFxFWkJYNuW2RmLXENBzqXXDOwu5XyVZQElhjVSzbhNvnfnEh0gqLNxYLXYtFPpO_YRQw';
    private const INVALID_SIGNATIRE_JWT = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.H3e47aFn4-ES1GQQ2bFxFWkJYNuW2RmLXENBzqXXDOwu5XyVZQElhjVSzbhNvnfnEh0gqLNxYLXYtFPpO_YRQw';
    private const EXPIRED_JWT           = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.A9VZhgivYCm2pfNpgh06NknetVrpF3w-60Dwuw41ea4td4qktOh7CV6TExb5hH2oR_osnvPbIONtcu643vnJqw';
    private const SECRET                = '123';
    private const PAYLOAD               = [
        'sub'  => '1234567890',
        'name' => 'John Doe',
        'iat'  => 1516239022,
    ];

    public function testCanDecodePayload(): void {
        $jwt = new Jwt(
            token: self::VALID_JWT,
            secret: self::SECRET,
        );

        $this->assertEquals((object) self::PAYLOAD, $jwt->getPayload());
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
            token: self::INVALID_SIGNATIRE_JWT,
            secret: self::SECRET,
        );

        $this->assertFalse($jwt->isValid());
    }

    public function testGeneratesToken(): void {
        $jwt = new Jwt(
            payload: (object) self::PAYLOAD,
            secret: self::SECRET,
        );

        $this->assertEquals($jwt->getToken(), self::VALID_JWT);
        $this->assertTrue($jwt->isValid());
    }

    public function testCanUpdateExpiration(): void {
        $jwt = new Jwt(
            payload: (object) self::PAYLOAD,
            secret: self::SECRET,
        );

        $expires = strtotime('August 29, 3097');

        $jwt->setExpiration($expires);

        $this->assertEquals($jwt->getPayload(), (object) [...self::PAYLOAD, 'exp' => $expires]);
        $this->assertTrue($jwt->isValid());
    }
}
