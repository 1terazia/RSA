//
// Created by Vladislav on 10/03/2023.
//

#ifndef RSA_RSA_H
#define RSA_RSA_H

#include<vector>
#include<random>
#include<cstdint>

class RSA {
private:
    static const int N = 100'000;

    std::vector<int> P;
    std::mt19937_64 rnd;

    void fill_primes();

    std::pair<__int128_t, __int128_t> Euclid(__int128_t, __int128_t) const;

    __int128_t reverse(__int128_t, __int128_t) const;

    __int128_t pow(__int128_t, __int128_t, __int128_t) const;

    __int128_t public_key, private_key, n, p, q;
public:
    RSA();

    RSA(__int128_t, __int128_t, __int128_t);

    __int128_t encrypted(__int128_t) const;

    __int128_t decrypted(__int128_t) const;

    __int128_t GetPublicKey() const;

    __int128_t GetPrivateKey() const;

    __int128_t GetModule() const;
};

#endif //RSA_RSA_H
