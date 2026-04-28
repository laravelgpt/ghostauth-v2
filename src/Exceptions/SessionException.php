<?php

declare(strict_types=1);

namespace GhostAuth\Exceptions;

/**
 * SessionException
 *
 * Thrown on session cookie read/decrypt/validate failures,
 * IP change detection, device mismatch, and tamper detection.
 *
 * @package GhostAuth\Exceptions
 */
class SessionException extends GhostAuthException {}
