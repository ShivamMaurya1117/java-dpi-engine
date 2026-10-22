package com.dpiengine.inspect;

/** Application identifiers from the original C++ types.h. TLS/QUIC are reserved here. */
public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC,
    GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM, NETFLIX, AMAZON, MICROSOFT,
    APPLE, WHATSAPP, TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE;

    public boolean isSpecific() {
        return switch (this) {
            case UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC -> false;
            default -> true;
        };
    }
}
