<?php

declare(strict_types=1);

namespace GhostAuth\Exceptions;

/** Thrown when an OTP cannot be delivered to its transport layer. */
class OtpTransportException extends GhostAuthException {}
