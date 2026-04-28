<?php

declare(strict_types=1);

namespace GhostAuth\Exceptions;

/** Thrown on JWT signing, verification, or revocation failures. */
class TokenException extends GhostAuthException {}
