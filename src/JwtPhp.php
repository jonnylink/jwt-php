<?php
namespace jonlink\Jwt;

use stdClass;
use Throwable;

class JwtPhp {
    private stdClass $payload;
    private string $secret;
    private string $token;

    private string $encoded_header;
    private string $algorithm;

    // a JWT is a base64 encoded, decimal deliminated string
    // all JWT are composed of these three parts: header.payload.signature
    private const PARTS = [
        'header'    => 0,
        'payload'   => 1,
        'signature' => 2, // the "signature" is made by combining the head, payload, and a secret
    ];

    // these never change, so there's no sense in wasting CPU encoding every time
    private const ENCODED_HEADERS = [
        'sha256' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', // {"alg":"HS256","typ":"JWT"}
        'sha512' => 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9', // {"alg":"HS512","typ":"JWT"}
    ];

    public function __construct(?string $token = null, ?stdClass $payload = null, string $secret = '', string $algorithm = 'sha512') {
        $this->algorithm = strtolower($algorithm);
        $this->validateAlgorithm();
        $this->encoded_header = self::ENCODED_HEADERS[$algorithm];

        $this->secret = $secret;

        if ($token && $payload) {
            throw new JwtPhpException('Cannot pass token and payload when instantiating.', 500);
        }

        if ($token) {
            $this->token = $token;
        }

        if ($payload) {
            $this->payload = $payload;
            $this->token   = $this->generateToken();
        }
    }

    private function validateAlgorithm(): void {
        $valid_algorithms = ['sha256', 'sha512'];

        if (!in_array($this->algorithm, $valid_algorithms)) {
            throw new JwtPhpException("Algorith `{$this->algorithm}` is not valid.", 500);
        }
    }

    private function decode(string $data): stdClass {
        // for some reason phpstan believes in its heart the return can be mixed
        // @phpstan-ignore return.type
        return json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $data))) ?? (object) [];
    }

    private function encode(string $data): string {
        return rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($data)), '=');
    }

    private function sign(string $encoded_header, string $encoded_payload): string {
        $hash_hmac_algo = $this->algoToHmacAlgo($this->decode($encoded_header)->alg);
        $signature      = hash_hmac(
            algo: $hash_hmac_algo,
            data: "{$this->encoded_header}.{$encoded_payload}",
            key: $this->secret,
            binary: true,
        );

        return $this->encode($signature);
    }

    private function algoToHmacAlgo(string $algo): string {
        return [
            'HS256' => 'sha256',
            'HS512' => 'sha512',
        ][$algo];
    }

    public function validate(): void {
        if ($this->isExpired()) {
            throw new JwtPhpException('Token is expired.', 401);
        }

        [$header, $payload, $signature] = explode('.', $this->getToken());

        $comparison_signature = $this->sign($header, $payload);

        if ($signature !== $comparison_signature) {
            throw new JwtPhpException('Token signature is not valid.', 401);
        }
    }

    private function generateToken(): string {
        if (!isset($this->payload)) {
            throw new JwtPhpException('Cannot generate token, payload not set.', 500);
        }

        $encoded_payload = $this->encode(json_encode($this->payload) ?: '');

        return "$this->encoded_header.$encoded_payload.{$this->sign($this->encoded_header, $encoded_payload)}";
    }

    public function isValid(): bool {
        try {
            $this->validate();

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    public function isExpired(): bool {
        $payload = $this->decode(explode('.', $this->getToken())[self::PARTS['payload']]);

        if (!isset($payload->exp)) {
            // if it doesn't expire it can't be expired
            return false;
        }

        if (time() > $payload->exp) {
            return true;
        }

        return false;
    }

    public function getPayload(): stdClass {
        $this->validate();

        return $this->decode(explode('.', $this->token)[self::PARTS['payload']]);
    }

    public function getHeader(): stdClass {
        return $this->decode(explode('.', $this->getToken())[self::PARTS['header']]);
    }

    public function getSignature(): string {
        return explode('.', $this->getToken())[self::PARTS['signature']];
    }

    public function getToken(): string {
        if (!isset($this->token)) {
            throw new JwtPhpException('Token not set', 500);
        }

        return $this->token;
    }

    public function setSecret(string $secret): self {
        $this->secret = $secret;

        return $this;
    }

    public function setPayload(string|stdClass $payload): self {
        if (is_string($payload)) {
            $payload = json_decode(json: $payload, associative: false);
        }

        if (!is_object($payload) || !is_a($payload, 'stdClass')) {
            $payload = (object) [];
        }

        $this->payload = $payload;

        return $this;
    }

    public function setIssuer(string $issuer): self {
        $this->setSupportedClaim('iss', $issuer);
        return $this;
    }

    public function setSubject(string|int $subject): self {
        $this->setSupportedClaim('sub', $subject);
        return $this;
    }

    public function setAudience(string $audience): self {
        $this->setSupportedClaim('aud', $audience);
        return $this;
    }

    public function setExpiration(int $expiration_timestamp): self {
        $this->setSupportedClaim('exp', $expiration_timestamp);
        return $this;
    }

    public function setNotBeforeTime(int $not_before_timestamp): self {
        $this->setSupportedClaim('nbf', $not_before_timestamp);
        return $this;
    }

    public function setIssuedAt(int $issued_at_timestamp): self {
        $this->setSupportedClaim('iat', $issued_at_timestamp);
        return $this;
    }

    public function setJwtId(string|int $jwt_id): self {
        $this->setSupportedClaim('jti', $jwt_id);
        return $this;
    }

    public function setClaim(string $claim, mixed $value): self {
        $this->payload->$claim = $value;
        $this->token           = $this->generateToken();
        return $this;
    }

    public function setSupportedClaim(string $claim, mixed $value): self {
        $supported_claims = [
            'iss' => 'issuer', // Issuer of the JWT
            'sub' => 'subject', // Subject of the JWT (the user)
            'aud' => 'audience', // Recipient for which the JWT is intended
            'exp' => 'expiration', // Time after which the JWT expires
            'nbf' => 'not before time', // Time before which the JWT must not be accepted for processing
            'iat' => 'issued at', // Time at which the JWT was issued; can be used to determine age of the JWT
            'jti' => 'JWT ID', // Unique identifier; can be used to prevent the JWT from being replayed (allows a token to be used only once)
        ];

        if (!isset($supported_claims[$claim])) {
            throw new JwtPhpException("Claim `$claim` is not supported", 500);
        }

        $this->setClaim($claim, $value);

        return $this;
    }
}
