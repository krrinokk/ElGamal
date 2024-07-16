using System;
using System.Numerics;

public class ElGamalEncryption
{
    private BigInteger p; // Простое число
    private BigInteger g; // Генератор
    private BigInteger privateKey; // Секретный ключ
    private BigInteger publicKey; // Открытый ключ

    // Конструктор класса
    public ElGamalEncryption(BigInteger p, BigInteger g, BigInteger privateKey)
    {
        this.p = p;
        this.g = g;
        this.privateKey = privateKey;
        // Вычисление открытого ключа
        this.publicKey = BigInteger.ModPow(g, privateKey, p); //нахождение Db
    }

    // Метод для шифрования сообщения
    public Tuple<BigInteger, BigInteger> Encrypt(BigInteger message, BigInteger receiverPublicKey, BigInteger randomK)
    {
        BigInteger r = BigInteger.ModPow(g, randomK, p);
        // Вычисление e
        BigInteger e = (message * BigInteger.ModPow(receiverPublicKey, randomK, p)) % p;
        return Tuple.Create(r, e); // Возвращаем зашифрованное сообщение в виде пары чисел (r, e)
    }

    // Метод для расшифрования сообщения
    public BigInteger Decrypt(Tuple<BigInteger, BigInteger> encryptedMessage)
    {
        BigInteger r = encryptedMessage.Item1;
        BigInteger e = encryptedMessage.Item2;
        // Вычисление обратного числа s по модулю p
        BigInteger s = BigInteger.ModPow(r, p - 1 - privateKey, p);
        return (e * s) % p; // Возвращаем расшифрованное сообщение
    }

    // Главная функция
    public static void Main(string[] args)
    {

        //BigInteger p = 23;
        //BigInteger g = 5;
        //BigInteger privateKeyB = 13; //C
        //BigInteger privateKeyA = 7; //k
        //BigInteger message = 15; //m



        BigInteger p = BigInteger.Parse("317023413423381373958357647853818713963498320651295691658096235012455055719786639082278518891127433451");
        BigInteger g = BigInteger.Parse("429363522649847");
        BigInteger privateKeyB = BigInteger.Parse("13"); //C
        BigInteger privateKeyA = BigInteger.Parse("7"); //k
        BigInteger message = BigInteger.Parse("1555555555555555555555555555555555555555555555555555555555555555555"); //m

        // Создание экземпляра класса для абонента В
        ElGamalEncryption elGamalB = new ElGamalEncryption(p, g, privateKeyB);
        BigInteger publicKeyB = elGamalB.publicKey; // Получение открытого ключа абонента В

        // Шифрование сообщения от абонента А к абоненту В
        Tuple<BigInteger, BigInteger> encryptedMessage = elGamalB.Encrypt(message, publicKeyB, privateKeyA);
        Console.WriteLine($"Encrypted message - (r, e): ({encryptedMessage.Item1}, {encryptedMessage.Item2})");

        // Расшифрование сообщения абонентом В
        BigInteger decryptedMessage = elGamalB.Decrypt(encryptedMessage);
        Console.WriteLine($"Decrypted message - m: {decryptedMessage}");
    }
}
