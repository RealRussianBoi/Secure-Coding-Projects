#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <ctime>

/// <summary>
/// encrypt or decrypt a source string using the provided key
/// </summary>
/// <param name="source">input string to process</param>
/// <param name="key">key to use in encryption / decryption</param>
/// <returns>transformed string</returns>
std::string encrypt_decrypt(const std::string& source, const std::string& key)
{
    const auto key_length = key.length();
    const auto source_length = source.length();
    assert(key_length > 0);
    assert(source_length > 0);

    std::string output = source;

    // loop through the source string char by char
    for (size_t i = 0; i < source_length; ++i)
    {
        // transform each character based on an xor of the key modded constrained to key length using a mod
        output[i] = source[i] ^ key[i % key_length];
    }

    assert(output.length() == source_length);
    return output;
}

std::string read_file(const std::string& filename)
{
    std::ifstream file(filename);
    std::stringstream buffer;
    if (!file)
    {
        std::cerr << "Error reading file: " << filename << std::endl;
        return "";
    }

    // TODO: implement loading the file into a string
    buffer << file.rdbuf();
    return buffer.str();
}

std::string get_student_name(const std::string& string_data)
{
    std::string student_name;
    size_t pos = string_data.find('\n');
    if (pos != std::string::npos)
    {
        student_name = string_data.substr(0, pos);
    }
    return student_name;
}

void save_data_file(const std::string& filename, const std::string& student_name, const std::string& key, const std::string& data)
{
    // TODO: implement file saving
    std::ofstream file(filename);
    if (!file)
    {
        std::cerr << "Error writing to file: " << filename << std::endl;
        return;
    }

    // Line 1: student name
    file << student_name << "\n";

    // Line 2: timestamp (yyyy-mm-dd)
    time_t now = time(nullptr);
    tm ltm;
    localtime_s(&ltm, &now);
    file << 1900 + ltm.tm_year << "-"
        << std::setfill('0') << std::setw(2) << 1 + ltm.tm_mon << "-"
        << std::setfill('0') << std::setw(2) << ltm.tm_mday << "\n";

    // Line 3: key used
    file << key << "\n";

    // Line 4+: data
    file << data;
}

int main()
{
    std::cout << "Encyption Decryption Test!" << std::endl;

    const std::string file_name = "inputdatafile.txt";
    const std::string encrypted_file_name = "encrypteddatafile.txt";
    const std::string decrypted_file_name = "decrytpteddatafile.txt";
    const std::string source_string = read_file(file_name);
    const std::string key = "password";

    const std::string student_name = get_student_name(source_string);
    const std::string encrypted_string = encrypt_decrypt(source_string, key);
    save_data_file(encrypted_file_name, student_name, key, encrypted_string);

    const std::string decrypted_string = encrypt_decrypt(encrypted_string, key);
    save_data_file(decrypted_file_name, student_name, key, decrypted_string);

    std::cout << "Read File: " << file_name
        << " - Encrypted To: " << encrypted_file_name
        << " - Decrypted To: " << decrypted_file_name << std::endl;
}