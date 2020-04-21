function FindProxyForURL(url, host) {
    if (host == '{{ domain }}')
        return 'PROXY {{ host }}:{{ port }}';
    return 'DIRECT';
}