<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * OtpTransportInterface
 *
 * Abstracts OTP delivery — the consuming app supplies a concrete implementation
 * backed by Mailgun, SendGrid, Twilio, AWS SNS, etc.
 *
 * @package GhostAuth\Contracts
 */
interface OtpTransportInterface
{
    /**
     * @param  string $recipient  Email address or E.164 phone number.
     * @param  string $otp        Plaintext OTP to deliver.
     * @param  string $channel    'email' | 'sms' | 'whatsapp'
     * @throws \GhostAuth\Exceptions\OtpTransportException
     */
    public function dispatch(string $recipient, string $otp, string $channel): bool;
}
