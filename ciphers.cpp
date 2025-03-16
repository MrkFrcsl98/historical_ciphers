#include <chrono>
#include <ctime>
#include <deque>
#include <functional>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

namespace Ciphers
{

#define _OP_MODULUS_ (std::uint8_t)0x01A // 26

namespace Utils
{
struct ExtGCDStruct
{
    long int X{0x0};
    long int Y{0x0};
};
static const std::size_t getGCD(const std::uint8_t x, const std::uint8_t y) noexcept
{
    std::size_t dvd{x}, dvs{y}, rm{0};
    while (dvs != 0x0)
    {
        rm = dvd % dvs;
        dvd = dvs;
        dvs = rm;
    }
    return dvd;
};

static const bool isCoprime(const std::uint8_t x, std::uint8_t y) noexcept
{
    return getGCD(x, y) == 0x1 ? true : false;
};

static const int extendedGCD(int a, int b, struct ExtGCDStruct &_s) noexcept
{
    int Q{0x0}, R{0x0}, x0{0x1}, y0{0x0}, x1{0x0}, y1{0x1}, tx{0x0}, ty{0x0};
    while (b != 0x0)
    {
        R = a % b;
        Q = a / b;
        a = b;
        b = R;
        tx = x0 - Q * x1;
        ty = y0 - Q * y1;
        x0 = x1;
        y0 = y1;
        x1 = tx;
        y1 = ty;
    }
    _s.X = x0;
    _s.Y = y0;
    return a;
};

static const int modInverse(const int a, const int b) noexcept
{
    struct ExtGCDStruct s;
    const int gcd{extendedGCD(a, b, s)};
    return (s.X % _OP_MODULUS_ + _OP_MODULUS_) % _OP_MODULUS_;
};

static const std::deque<std::uint8_t> generateVigenKeystream(const std::string_view& _msg) noexcept {
  std::deque<std::uint8_t> ks(_msg.length());
  std::size_t state = std::time(nullptr);
  std::function<std::size_t(int)> gen = [&state] (int base) {
    state ^= state << 0x0d;
    state ^= state >> 0x07;
    state ^= state << 0x11;
    return base + (state % (base + 0x1au - base));
  };
  for(std::size_t i{0x0}; i < ks.size(); ++i) {
    ks[i] = gen(isupper(_msg[i]) ? 0x41 : 0x61);
  }
  return ks;
};

}; // namespace Utils

class Ceasar
{

    std::uint16_t _key;

  public:
    Ceasar() = delete;
    Ceasar(const Ceasar &copy) = delete;
    Ceasar(Ceasar &&copy) = delete;
    explicit Ceasar(const std::uint16_t _k) noexcept : _key(_k) {};

    const std::string byteTransformation(const std::string_view _pt)
    {
        std::string _out;
        _out.reserve(_pt.length());

        if (_pt.length() > 0x0) [[likely]]
        {
            if (this->_key == 0x0) [[unlikely]]
            {
                return _pt.data();
            }
            else if (this->_key > _OP_MODULUS_) [[unlikely]]
            {
                this->_key %= _OP_MODULUS_;
            }
        }
        else [[unlikely]]
        {
            throw std::invalid_argument("input size must be > 0!");
        }
        for (const char byte : _pt)
        {
            if (isalpha(byte) > 0x0) [[likely]]
            {
                const int base{isupper(byte) ? 'A' : 'a'};
                _out.push_back(((byte - base + this->_key + _OP_MODULUS_) % _OP_MODULUS_) + base);
            }
            else
            {
                _out.push_back(byte);
            }
        }

        return _out;
    };

    const std::string byteReverse(const std::string_view &_ct)
    {
        std::string _out;
        _out.reserve(_ct.length());
        if (_ct.length() > 0x0) [[likely]]
        {
            for (const char byte : _ct)
            {
                if (isalpha(byte)) [[likely]]
                {
                    const int base{isupper(byte) ? 'A' : 'a'};
                    _out.push_back(((byte - base - this->_key + _OP_MODULUS_) % _OP_MODULUS_) +
                                   base);
                }
                else
                {
                    _out.push_back(byte);
                }
            }
        }
        else [[unlikely]]
        {
            throw std::invalid_argument("ciphertext is empty!");
        }
        return _out;
    };

    ~Ceasar()
    {
        this->_key = 0; // get rid of key...
    };
};

class Affine
{

    std::uint8_t _kA;
    std::uint8_t _kB;

  public:
    Affine() = delete;
    Affine(const Affine &copy) = delete;
    Affine(Affine &&copy) = delete;

    explicit Affine(const std::uint8_t kA, const std::uint8_t kB) noexcept : _kA(kA), _kB(kB) {};

    const std::string byteTransformation(const std::string_view _pt)
    {
        std::string _out;
        _out.reserve(_pt.length());
        if (Utils::getGCD(this->_kA, _OP_MODULUS_) != 0x01)
            throw std::runtime_error("Not coprime kA!");
        if (_pt.length() > 0x0) [[likely]]
        {
            if (this->_kA == 0x0 && this->_kB == 0x0) [[unlikely]]
            {
                return _pt.data();
            }
            else if (this->_kA > _OP_MODULUS_) [[unlikely]]
            {
                this->_kA %= _OP_MODULUS_;
            }
        }
        else [[unlikely]]
        {
            throw std::invalid_argument("input size must be > 0!");
        }
        for (const std::uint8_t byte : _pt)
        {
            if (isalpha(byte) > 0x0) [[likely]]
            {
                const int base{isupper(byte) ? 'A' : 'a'};
                _out.push_back((this->_kA * (byte - base) + this->_kB) % _OP_MODULUS_ + base);
            }
            else
            {
                _out.push_back(byte);
            }
        }
        return _out;
    };

    const std::string byteReverse(const std::string_view &_ct)
    {
        std::string _out;
        _out.reserve(_ct.length());
        if (_ct.length() > 0x0) [[likely]]
        {
            const int mod_inverse{Utils::modInverse(this->_kA, _OP_MODULUS_)};
            for (const std::uint8_t byte : _ct)
            {
                if (isalpha(byte)) [[likely]]
                {
                    const int base{isupper(byte) ? 'A' : 'a'};
                    _out.push_back((mod_inverse * ((byte - base) - this->_kB + _OP_MODULUS_)) %
                                       _OP_MODULUS_ +
                                   base);
                }
                else
                {
                    _out.push_back(byte);
                }
            }
        }
        else [[unlikely]]
        {
            throw std::invalid_argument("ciphertext is empty!");
        }
        return _out;
    };

    ~Affine() {};
};

class Vigenere
{

    std::deque<std::uint8_t> _keystream;

  public:
    Vigenere() = delete;
    Vigenere(const Vigenere &copy) = delete;
    Vigenere(Vigenere &&copy) = delete;
    Vigenere(const std::deque<std::uint8_t> &_ks) noexcept : _keystream(_ks) {};
    const std::string byteTransformation(const std::string_view _pt)
    {
        std::string _out;
        _out.reserve(_pt.length());

        if (_pt.length() > 0x0) [[likely]]
        {
            if (this->_keystream.size() == 0x0) [[unlikely]]
            {
                return _pt.data();
            }
            else if (this->_keystream.size() > _pt.length()) [[unlikely]]
            {
                this->_keystream.erase(this->_keystream.begin() + _pt.length(),
                                       this->_keystream.end());
            }
        }
        else [[unlikely]]
        {
            throw std::invalid_argument("input size must be > 0!");
        }
        for (std::size_t i{0}; i < _pt.length() && i < this->_keystream.size(); ++i)
        {
            if (isalpha(_pt[i]) > 0x0) [[likely]]
            {
                const int base{isupper(_pt[i]) ? 'A' : 'a'};
                int byte = _pt[i] - base;
                char computed_byte = (byte + this->_keystream[i] - base) % _OP_MODULUS_ + base;
                _out.push_back(computed_byte);
            }
            else
            {
                _out.push_back(_pt[i]);
            }
        }

        return _out;
    };

    const std::string byteReverse(const std::string_view &_ct)
    {
        std::string _out;
        _out.reserve(_ct.length());
        if (_ct.length() > 0x0) [[likely]]
        {
            for (std::size_t i{0x0}; i < _ct.length() && i < this->_keystream.size(); ++i)
            {
                if (isalpha(_ct[i])) [[likely]]
                {
                    const int base{isupper(_ct[i]) ? 'A' : 'a'};
                    int byte = _ct[i] - base;
                    char computed_byte =
                        (byte - (this->_keystream[i] - base) + _OP_MODULUS_) % _OP_MODULUS_ + base;
                    _out.push_back(computed_byte);
                }
                else
                {
                    _out.push_back(_ct[i]);
                }
            }
        }
        else [[unlikely]]
        {
            throw std::invalid_argument("ciphertext is empty!");
        }

        return _out;
    };
    ~Vigenere() {};
};
}; // namespace Ciphers

int main(int argc, char **argv)
{

    const std::string message("secret Message 123...");

    /**********************************************************************\
    \************************* Ceasar Cipher ******************************/
    try
    {
        std::cout << "\n******************** CEASAR CIPHER **********************\n";
        Ciphers::Ceasar ceasar(0x03);

        const std::string encrypted = ceasar.byteTransformation(message);
        std::cout << "Ceasar Cipher Encrypted:    " << encrypted << "\n";

        const std::string decrypted = ceasar.byteReverse(encrypted);
        std::cout << "Ceasar Cipher Decrypted:    " << decrypted << "\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Ceasar Exception: " << e.what() << "\n";
    }

    /**********************************************************************\
    \************************* Affine Cipher ******************************/
    try
    {
        std::cout << "\n******************** AFFINE CIPHER **********************\n";
        Ciphers::Affine affine(0x03, 0x09);

        const std::string encrypted = affine.byteTransformation(message);
        std::cout << "Affine Cipher Encrypted:    " << encrypted << "\n";

        const std::string decrypted = affine.byteReverse(encrypted);
        std::cout << "Affine Cipher Decrypted:    " << decrypted << "\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Affine Exception: " << e.what() << "\n";
    }

    /**********************************************************************\
    \************************* Vigenere Cipher ****************************/
    try
    {
        std::cout << "\n******************** VIGENERE CIPHER **********************\n";
        std::deque<std::uint8_t> ks(Ciphers::Utils::generateVigenKeystream(message));
        std::cout << "Keystream: ";
        for(auto x: ks) std::cout << x;
        std::cout << "\n";
        Ciphers::Vigenere vigenere(ks);

        const std::string encrypted = vigenere.byteTransformation(message);
        std::cout << "Vigenere Cipher Encrypted:  " << encrypted << "\n";

        const std::string decrypted = vigenere.byteReverse(encrypted);
        std::cout << "Vigenere Cipher Decrypted:  " << decrypted << "\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Vigenere Exception: " << e.what() << "\n";
    }
    return 0;
}
