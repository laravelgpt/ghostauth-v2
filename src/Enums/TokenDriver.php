<?php

declare(strict_types=1);

namespace GhostAuth\Enums;

/**
 * TokenDriver
 *
 * Backed enum representing how GhostAuth issues and validates tokens.
 *
 * @package GhostAuth\Enums
 */
enum TokenDriver: string
{
    /** Stateless JWT — embedded claims, verified via signature. */
    case Jwt = 'jwt';

    /** Stateful session — opaque token stored in server-side cache. */
    case Session = 'session';
}
