<?php
namespace jonlink\Jwt;

use stdClass;
use Throwable;

class JwtPhp {
    protected stdClass $payload;
    protected string $secret;
    protected string $signature;
    protected string $token;

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

    public function __construct(?string $token = null, ?string $secret = null, string $algorithm = 'sha512') {
        $this->algorithm = strtolower($algorithm);
        $this->validateAlgorithm();
        $this->encoded_header = self::ENCODED_HEADERS[$algorithm];

        if ($token) {
            $this->token = $token;
        }

        if ($secret) {
            $this->secret = $secret;
        }
    }

    private function validateAlgorithm(): void {
        $valid_algorithms = ['sha256', 'sha512'];

        if (!in_array($this->algorithm, $valid_algorithms)) {
            throw new JwtPhpException("Algorith `{$this->algorithm}` is not valid.", 500);
        }
    }

    protected function decode(string $data): stdClass {
        // for some reason phpstan believes in its heart the return can be mixed
        // @phpstan-ignore return.type
        return json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $data))) ?? (object) [];
    }

    protected function encode(string $data): string {
        return rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($data)), '=');
    }

    protected function sign(string $encoded_header, string $encoded_payload, string $secret): string {
        $hash_hmac_algo = $this->algoToHmacAlgo($this->decode($encoded_header)->alg);
        $signature      = hash_hmac(
            algo: $hash_hmac_algo,
            data: "{$this->encoded_header}.{$encoded_payload}",
            key: $secret,
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

        $comparison_signature = $this->sign($header, $payload, $this->secret);

        if ($signature !== $comparison_signature) {
            throw new JwtPhpException('Token signature is not valid.', 401);
        }
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

    public function payload(): stdClass {
        $this->validate();

        return $this->decode(explode('.', $this->token)[self::PARTS['payload']]);
    }

    public function header(): stdClass {
        return $this->decode(explode('.', $this->getToken())[self::PARTS['header']]);
    }

    public function signature(): string {
        return explode('.', $this->getToken())[self::PARTS['signature']];
    }

    public function setSecret(string $secret): self {
        $this->secret = $secret;

        return $this;
    }

    public function getToken(): string {
        if (!isset($this->token)) {
            throw new JwtPhpException('Token not set', 500);
        }

        return $this->token;
    }
}
