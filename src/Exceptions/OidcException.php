<?php

declare(strict_types=1);

namespace GhostAuth\Exceptions;

/** Thrown on OIDC discovery, ID Token validation, or nonce failures. */
class OidcException extends GhostAuthException {}
