#include "rsa.h"

void RSA::fill_primes() {
    if (!P.empty())
        return;
    std::vector<int> arr(N);
    for (int x = 2; x < N; ++x) {
        if (arr[x]) {
            continue;
        }
        arr[x] = 1;
        for (int y = 2 * x; y < N; y += x) {
            arr[y] = 2;
        }
    }
    for (int x = 0; x < N; ++x) {
        if (arr[x] == 1) {
            P.push_back(x);
        }
    }
}

std::pair<__int128_t, __int128_t> RSA::Euclid(__int128_t x, __int128_t y) const {
    if (y == 0) {
        return {1, 0};
    }
    auto ans = Euclid(y, x % y);
    return {ans.second, ans.first - (x / y) * ans.second};
}

__int128_t RSA::reverse(__int128_t x, __int128_t MOD) const {
    auto ans = Euclid(x, MOD);
    if (ans.first * x + MOD * ans.second == 1) {
        if (ans.first < 0) {
            ans.first += MOD;
        }
        return ans.first;
    }
    if (ans.second < 0) {
        ans.second += MOD;
    }
    return ans.second;
}

__int128_t RSA::pow(__int128_t x, __int128_t power, __int128_t mod) const {
    if (power == 1) {
        return x % mod;
    }
    if (power == 0) {
        return 1ll;
    }
    __int128_t a = pow(x, power >> 1, mod);
    if (power & 1) {
        return (((a * a) % mod) * x) % mod;
    }
    return (a * a) % mod;
}

RSA::RSA() : rnd(12) {
    fill_primes();
    p = P[rnd() % P.size()];
    q = P[rnd() % P.size()];
    n = p * q;
    __int128_t euler = (p - 1) * (q - 1);
    int l = 0, r = static_cast<int> (P.size());
    while (r - l > 1) {
        int m = (l + r) >> 1;
        if (P[m] >= euler) {
            r = m;
        } else {
            l = m;
        }
    }
    public_key = P[rnd() % (l + 1)];
    while (public_key == p || public_key == q) {
        public_key = P[rnd() % (l + 1)];
    }
    private_key = reverse(public_key, (q - 1) * (p - 1));
}

RSA::RSA(__int128_t mod, __int128_t e, __int128_t d) {
    fill_primes();
    n = mod;
    public_key = e;
    private_key = d;
}

__int128_t RSA::encrypted(__int128_t m) const {
    return RSA::pow(m, public_key, n);
}

__int128_t RSA::decrypted(__int128_t m) const {
    return pow(m, private_key, n);
}

__int128_t RSA::GetPublicKey() const {
    return public_key;
}

__int128_t RSA::GetPrivateKey() const {
    return private_key;
}

__int128_t RSA::GetModule() const {
    return n;
}