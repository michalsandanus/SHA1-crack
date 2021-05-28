#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include "sha1.hpp"

#define MIN_PASSWORD_LENGTH 1
#define MAX_PASSWORD_LENGTH 32

#define DIGIT_START 48
#define DIGIT_END 57

#define UPPER_CASE_START 65
#define UPPER_CASE_END 90

#define LOWER_CASE_START 97
#define LOWER_CASE_END 122

#define NUM_OF_CHAR 62

#define CHECKPOINT 100000

#define DIGIT 0
#define UPPER_CASE 1
#define LOWER_CASE 2
#define ANY_CHAR 3

size_t password_counter = 0;

typedef struct sectionPattern {
	int min_length;
	int max_length;
	char character;
} sectionPattern;


void checkPasswordCounter(std::chrono::time_point<std::chrono::system_clock>& time, std::string actualPassword) {
	if (password_counter >= CHECKPOINT) {
		std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
		std::chrono::duration<double> duration = now - time;
		double avg = static_cast<double>(password_counter) / static_cast<double>(duration.count());

		std::cout << "Average number of password checked per second: " << round(avg) << std::endl;
		std::cout << "Actual password checking: \"" << actualPassword << "\"" << std::endl;

		password_counter = 0;
		time = std::chrono::system_clock::now();
	}
}

std::string convertInputHash(std::string inputHash) {
	std::string convertedHash = "";
	
	for (std::string::iterator it = inputHash.begin(); it != inputHash.end(); ++it) {
		if (*it <= 'Z' && *it >= 'A') {
			convertedHash += *it - ('Z' - 'z');
		}
		else convertedHash += *it;
	}

	return convertedHash;
}

bool checkInputHash(std::string inputHash) {
	if (inputHash.length() != 40) return false;
	
	for (std::string::iterator it = inputHash.begin(); it != inputHash.end(); ++it) {
		if ((*it < '0' || *it > '9') && (*it < 'a' || *it > 'f')) return false;
	}

	return true;
}

void hashPassword(std::string password, std::string inputHash, bool flag_salt, std::string salt, 
	bool& passwordFound, std::chrono::time_point<std::chrono::system_clock>& time) {
	password_counter++;
	checkPasswordCounter(time, password);
	
	if (flag_salt) {
		SHA1 hash1;
		hash1.update(salt + password);

		if (inputHash == hash1.final()) {
			std::cout << std::endl << "Correct password found." << std::endl;
			std::cout << "The password is \"" << password << "\" and is preceded by salt \"" << salt << "\"" << std::endl;
			std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
			std::cout << "*******************************************************************************************" << std::endl << std::endl;
			passwordFound = true;
			return;
		}

		SHA1 hash2;
		hash2.update(password + salt);

		if (inputHash == hash2.final()) {
			std::cout << std::endl << "Correct password found." << std::endl;
			std::cout << "The password is \"" << password << "\" and is followed by salt \"" << salt << "\"" << std::endl;
			std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
			std::cout << "*******************************************************************************************" << std::endl << std::endl;
			passwordFound = true;
			return;
		}
	}

	SHA1 hash;
	hash.update(password);

	if (inputHash == hash.final()) {
		std::cout << std::endl << "Correct password found." << std::endl;
		std::cout << "The password is \"" << password << "\"" << std::endl;
		std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
		std::cout << "*******************************************************************************************" << std::endl << std::endl;
		passwordFound = true;
		return;
	}

	return;
}

void hashPasswordVector(std::vector<std::string> vecPasswords, std::string inputHash, bool flag_salt, std::string salt, bool& passwordFound) {
	for (std::string& password : vecPasswords) {
		if (flag_salt) {
			SHA1 hash1;
			hash1.update(salt + password);

			if (inputHash == hash1.final()) {
				std::cout << std::endl << "Correct password found." << std::endl;
				std::cout << "The password is \"" << password << "\" and is preceded by salt \"" << salt << "\"" << std::endl;
				std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
				std::cout << "*******************************************************************************************" << std::endl << std::endl;
				passwordFound = true;
				return;
			}

			SHA1 hash2;
			hash2.update(password + salt);

			if (inputHash == hash2.final()) {
				std::cout << std::endl << "Correct password found." << std::endl;
				std::cout << "The password is \"" << password << "\" and is followed by salt \"" << salt << "\"" << std::endl;
				std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
				std::cout << "*******************************************************************************************" << std::endl << std::endl;
				passwordFound = true;
				return;
			}
		}

		SHA1 hash;
		hash.update(password);

		if (inputHash == hash.final()) {
			std::cout << std::endl << "Correct password found." << std::endl;
			std::cout << "The password is \"" << password << "\"" << std::endl;
			std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
			std::cout << "*******************************************************************************************" << std::endl << std::endl;
			passwordFound = true;
			return;
		}
	}
	return;
}

void generatePassword(unsigned int length, std::string s, std::string inputHash, bool flag_salt, std::string salt,
	bool &passwordFound, bool flag_multithread, std::chrono::time_point<std::chrono::system_clock>& time)
{
	if (passwordFound) return;

	if (flag_multithread && length == 1) {
		std::vector<std::string> vecPasswordsDigits;
		std::vector<std::string> vecPasswordsUpperCase;
		std::vector<std::string> vecPasswordsLowerCase;

		//digits
		for (unsigned int i = DIGIT_START; i <= DIGIT_END; i++) vecPasswordsDigits.push_back(s + static_cast<char>(i));

		//upper case letters
		for (unsigned int i = UPPER_CASE_START; i <= UPPER_CASE_END; i++) vecPasswordsUpperCase.push_back(s + static_cast<char>(i));
			
		//lower case letters
		for (unsigned int i = LOWER_CASE_START; i <= LOWER_CASE_END; i++) vecPasswordsLowerCase.push_back(s + static_cast<char>(i));

		std::thread t1(hashPasswordVector, vecPasswordsDigits, inputHash, flag_salt, salt, std::ref(passwordFound));
		std::thread t2(hashPasswordVector, vecPasswordsUpperCase, inputHash, flag_salt, salt, std::ref(passwordFound));
		std::thread t3(hashPasswordVector, vecPasswordsLowerCase, inputHash, flag_salt, salt, std::ref(passwordFound));
		t1.join();
		t2.join();
		t3.join();

		password_counter += NUM_OF_CHAR;
		checkPasswordCounter(time, vecPasswordsDigits[0]);

		return;
	}

	else if (length == 0){
		hashPassword(s, inputHash, flag_salt, salt, passwordFound, time);
		return;
	}

	//digits
	for (unsigned int i = DIGIT_START; i <= DIGIT_END; i++) generatePassword(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt, 
		passwordFound, flag_multithread, time);

	//upper case letters
	for (unsigned int i = UPPER_CASE_START; i <= UPPER_CASE_END; i++) generatePassword(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt,
		passwordFound, flag_multithread, time);

	//lower case letters
	for (unsigned int i = LOWER_CASE_START; i <= LOWER_CASE_END; i++) generatePassword(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt, 
		passwordFound, flag_multithread, time);

	return;
}

void generateBasePattern(int length, std::string s, std::string inputHash, bool flag_salt, std::string salt, std::vector<char> vecPattern,
	bool& passwordFound, bool flag_multithread, std::chrono::time_point<std::chrono::system_clock>& time) {

	if (passwordFound) return;

	if (flag_multithread && length == 1) {
		std::vector<std::string> vecPasswords;

		//digits
		if (vecPattern[vecPattern.size() - length] == DIGIT) {
			for (unsigned int i = DIGIT_START; i <= DIGIT_END; i++) vecPasswords.push_back(s + static_cast<char>(i));
		}

		//upper case
		else if (vecPattern[vecPattern.size() - length] == UPPER_CASE) {
			for (unsigned int i = UPPER_CASE_START; i <= UPPER_CASE_END; i++) vecPasswords.push_back(s + static_cast<char>(i));
		}

		//lower case
		else if (vecPattern[vecPattern.size() - length] == LOWER_CASE) {
			for (unsigned int i = LOWER_CASE_START; i <= LOWER_CASE_END; i++) vecPasswords.push_back(s + static_cast<char>(i));
		}

		//any character
		else if (vecPattern[vecPattern.size() - length] == ANY_CHAR) {
			for (unsigned int i = DIGIT_START; i <= DIGIT_END; i++)	vecPasswords.push_back(s + static_cast<char>(i));
			for (unsigned int i = UPPER_CASE_START; i <= UPPER_CASE_END; i++) vecPasswords.push_back(s + static_cast<char>(i));
			for (unsigned int i = LOWER_CASE_START; i <= LOWER_CASE_END; i++) vecPasswords.push_back(s + static_cast<char>(i));
		}

		//concrete character
		else vecPasswords.push_back(s + vecPattern[vecPattern.size() - length]);

		//split vector into three
		std::vector<std::string> vecPasswords1;
		std::vector<std::string> vecPasswords2;
		std::vector<std::string> vecPasswords3;

		for (size_t i = 0; i < vecPasswords.size(); i++) {
			if (i < vecPasswords.size() / 3) vecPasswords1.push_back(vecPasswords[i]);
			else if (i < vecPasswords.size() / 3 * 2) vecPasswords2.push_back(vecPasswords[i]);
			else vecPasswords3.push_back(vecPasswords[i]);
		}
		

		std::thread t1(hashPasswordVector, vecPasswords1, inputHash, flag_salt, salt, std::ref(passwordFound));
		std::thread t2(hashPasswordVector, vecPasswords2, inputHash, flag_salt, salt, std::ref(passwordFound));
		std::thread t3(hashPasswordVector, vecPasswords3, inputHash, flag_salt, salt, std::ref(passwordFound));
		t1.join();
		t2.join();
		t3.join();

		password_counter += vecPasswords.size();
		checkPasswordCounter(time, vecPasswords[0]);

		return;
	}

	else if (length == 0) {
		hashPassword(s, inputHash, flag_salt, salt, passwordFound, time);
		return;
	}

	//digits 
	if (vecPattern[vecPattern.size() - length] == DIGIT) {
		for (unsigned int i = DIGIT_START; i <= DIGIT_END; i++)	generateBasePattern(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt,
			vecPattern, passwordFound, flag_multithread, time);
	}

	//upper case letters
	else if (vecPattern[vecPattern.size() - length] == UPPER_CASE) {
		for (unsigned int i = UPPER_CASE_START; i <= UPPER_CASE_END; i++) generateBasePattern(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt,
			vecPattern, passwordFound, flag_multithread, time);
	}

	//lower case letters
	else if (vecPattern[vecPattern.size() - length] == LOWER_CASE) {
		for (unsigned int i = LOWER_CASE_START; i <= LOWER_CASE_END; i++) generateBasePattern(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt,
			vecPattern, passwordFound, flag_multithread, time);
	}

	//any letter
	else if (vecPattern[vecPattern.size() - length] == ANY_CHAR) {
		for (unsigned int i = DIGIT_START; i <= DIGIT_END; i++)	generateBasePattern(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt,
			vecPattern, passwordFound, flag_multithread, time);
		for (unsigned int i = UPPER_CASE_START; i <= UPPER_CASE_END; i++)	generateBasePattern(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt,
			vecPattern, passwordFound, flag_multithread, time);
		for (unsigned int i = LOWER_CASE_START; i <= LOWER_CASE_END; i++)	generateBasePattern(length - 1, s + static_cast<char>(i), inputHash, flag_salt, salt,
			vecPattern, passwordFound, flag_multithread, time);
	}

	//concrete letter
	else generateBasePattern(length - 1, s + vecPattern[vecPattern.size() - length], inputHash, flag_salt, salt, vecPattern, passwordFound, flag_multithread, time);

	return;
}

std::vector<char> createBasePatternFromExtended(std::vector<sectionPattern> vecSectionsPattern, std::vector<int> vecIncrease) {
	std::vector<char> vecPattern;

	for (int i = 0; i < static_cast<int>(vecSectionsPattern.size()); i++) {
		for (int j = 0; j < vecSectionsPattern[i].min_length; j++) {
			vecPattern.push_back(vecSectionsPattern[i].character);
		}
		for (int j = 0; j < vecIncrease[i]; j++) {
			vecPattern.push_back(vecSectionsPattern[i].character);
		}
	}

	return vecPattern;
}

int getExtendedPatternMinLength(std::vector<sectionPattern> vecSectionsPattern) {
	int min_length = 0;
	for (int i = 0; i < static_cast<int>(vecSectionsPattern.size()); i++) {
		min_length += vecSectionsPattern[i].min_length;
	}
	return min_length;
}

// functions findNumbers(), combinationSum() and findCombinations were copied and adapted to my program from https://www.geeksforgeeks.org/combinational-sum/
void findNumbers(std::vector<int>& ar, int sum, std::vector<std::vector<int> >& res, std::vector<int>& r, int i)
{
	// If  current sum becomes negative
	if (sum < 0)
		return;

	// if we get exact answer
	if (sum == 0)
	{
		res.push_back(r);
		return;
	}

	// Recur for all remaining elements that
	// have value smaller than sum.
	while (i < static_cast<int>(ar.size()) && sum - ar[i] >= 0)
	{

		// Till every element in the array starting
		// from i which can contribute to the sum
		r.push_back(ar[i]); // add them to list

		// recur for next numbers
		findNumbers(ar, sum - ar[i], res, r, i);
		i++;

		// remove number from list (backtracking)
		r.pop_back();
	}
}

std::vector<std::vector<int>> combinationSum(std::vector<int>& ar, int sum)
{
	// sort input array
	sort(ar.begin(), ar.end());

	// remove duplicates
	ar.erase(unique(ar.begin(), ar.end()), ar.end());

	std::vector<int> r;
	std::vector<std::vector<int>> res;
	findNumbers(ar, sum, res, r, 0);

	return res;
}

std::vector<std::vector<int>> findCombinations(int sum) {
	std::vector<int> ar;
	for (int i = 1; i <= MAX_PASSWORD_LENGTH; i++) {
		ar.push_back(i);
	}

	std::vector<std::vector<int> > res = combinationSum(ar, sum);
	return res;
}

bool checkIncreaseConditions(std::vector<sectionPattern> vecSectionsPattern, std::vector<int> vecIncrease) {
	for (size_t i = 0; i < vecSectionsPattern.size(); i++) {
		if (vecSectionsPattern[i].min_length + vecIncrease[i] > vecSectionsPattern[i].max_length) return false;
	}

	return true;
}

void generateExtendedPattern(std::vector<sectionPattern>& vecSectionsPattern, std::string inputHash, bool flag_salt, std::string salt, bool flag_multithread) {
	std::vector<int> vecMinLength;
	std::vector<char> vecBasePattern;
	
	std::vector<int> vecIncrease;
	for (int section = 0; section < static_cast<int>(vecSectionsPattern.size()); section++) {
		vecIncrease.push_back(0);
	}

	int min_length = getExtendedPatternMinLength(vecSectionsPattern);

	bool passwordFound = false;
	std::chrono::time_point<std::chrono::system_clock> time = std::chrono::system_clock::now();

	if (min_length != 0) {
		vecBasePattern = createBasePatternFromExtended(vecSectionsPattern, vecIncrease);
		generateBasePattern(static_cast<int>(vecBasePattern.size()), "", inputHash, flag_salt, salt, vecBasePattern, passwordFound, flag_multithread, time);
		if (passwordFound) return;
	}

	for (int i = min_length + 1; i <= MAX_PASSWORD_LENGTH; i++) {
		std::vector<std::vector<int>> combinations = findCombinations(i - min_length);
		for (int j = 0; j < static_cast<int>(combinations.size()); j++) {
			if (combinations[j].size() > vecSectionsPattern.size()) continue;
			else if (combinations[j].size() < vecSectionsPattern.size()) {
				while (combinations[j].size() != vecSectionsPattern.size()) {
					combinations[j].push_back(0);
				}
			}

			sort(combinations[j].begin(), combinations[j].end());

			do {
				if (checkIncreaseConditions(vecSectionsPattern, combinations[j])) {
					vecBasePattern = createBasePatternFromExtended(vecSectionsPattern, combinations[j]);
					generateBasePattern(static_cast<int>(vecBasePattern.size()), "", inputHash, flag_salt, salt, vecBasePattern, passwordFound, flag_multithread, time);
					if (passwordFound) return;
				}
			} while (std::next_permutation(combinations[j].begin(), combinations[j].end()));
		}
	}

	if (!passwordFound) {
		std::cout << "Password was not found for hash: " << inputHash << ". Password has reached its maximal length." << std::endl << std::endl;
		std::cout << "*******************************************************************************************" << std::endl << std::endl;
	}

	return;
}

void bruteForce(std::string inputHash, bool flag_salt, std::string salt, bool flag_multithread) {
	bool passwordFound = false;

	std::chrono::time_point<std::chrono::system_clock> time;
	time = std::chrono::system_clock::now();

	for (int i = 1; i <= MAX_PASSWORD_LENGTH; i++) {
		std::cout << "Actual password length checking: " << i << std::endl;
		generatePassword(i, "", inputHash, flag_salt, salt, passwordFound, flag_multithread, time);

		if (passwordFound) return;
	}

	if (!passwordFound) {
		std::cout << "Password was not found for hash: " << inputHash << ". Password has reached its maximal length." << std::endl << std::endl;
		std::cout << "*******************************************************************************************" << std::endl << std::endl;
	}
	return;
}

bool checkDictionary(std::string inputHash, std::ifstream &dictionary, bool flag_salt, std::string salt) {
	std::string dictPassword = "";

	dictionary.clear();
	dictionary.seekg(0);

	std::cout << "Checking dictionary passwords..." << std::endl;

	while (std::getline(dictionary, dictPassword)) {
		if (flag_salt) {
			SHA1 hash1;
			hash1.update(salt + dictPassword);

			if (inputHash == hash1.final()) {
				std::cout << std::endl << "Correct password found in dictionary." << std::endl;
				std::cout << "The password is \"" << dictPassword << "\" and is preceded by salt \"" << salt << "\"" << std::endl;
				std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
				std::cout << "*******************************************************************************************" << std::endl << std::endl;
				return true;
			}

			SHA1 hash2;
			hash2.update(dictPassword + salt);

			if (inputHash == hash2.final()) {
				std::cout << std::endl << "Correct password found in dictionary." << std::endl;
				std::cout << "The password is \"" << dictPassword << "\" and is followed by salt \"" << salt << "\"" << std::endl;
				std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
				std::cout << "*******************************************************************************************" << std::endl << std::endl;
				return true;
			}
		}

		else {
			SHA1 hash;
			hash.update(dictPassword);

			if (inputHash == hash.final()) {
				std::cout << std::endl << "Correct password found in dictionary." << std::endl;
				std::cout << "The password is \"" << dictPassword << "\"" << std::endl;
				std::cout << "Input hash: \"" << inputHash << "\"" << std::endl << std::endl;
				std::cout << "*******************************************************************************************" << std::endl << std::endl;
				return true;
			}
		}
	}

	return false;
}

std::vector<sectionPattern> parseExtendedPattern(std::string pattern) {
	std::vector<sectionPattern> vecSectionsPattern;
	bool flag_backslash = false;
	bool flag_bracket_open = false;

	bool first_num = true;
	std::string first_num_str = "";
	std::string second_num_str = "";

	for (std::string::iterator it = pattern.begin(); it != pattern.end(); ++it) {
		if (flag_backslash && !flag_bracket_open) {
			if (*it == 'A') {
				sectionPattern section{ 1,1,UPPER_CASE };
				vecSectionsPattern.push_back(section);
				flag_backslash = false;
			}
			else if (*it == 'a') {
				sectionPattern section{ 1,1,LOWER_CASE };
				vecSectionsPattern.push_back(section);
				flag_backslash = false;
			}
			else if (*it == 'd') {
				sectionPattern section{ 1,1,DIGIT };
				vecSectionsPattern.push_back(section);
				flag_backslash = false;
			}
			else {
				std::cout << "Pattern \"" << pattern << "\" is not valid pattern." << std::endl;
				std::cout << "*******************************************************************************************" << std::endl << std::endl;
				exit(1);
			}
		}

		else if (flag_bracket_open && !flag_backslash) {
			if (*it == ',') {
				first_num = false;
			}
			else if (*it == '}') {
				flag_bracket_open = false;
				vecSectionsPattern[vecSectionsPattern.size() - 1].min_length = std::stoi(first_num_str);
				vecSectionsPattern[vecSectionsPattern.size() - 1].max_length = std::stoi(second_num_str);
				first_num_str = "";
				second_num_str = "";
			}
			else if (first_num) {
				first_num_str += *it;
			}
			else {
				second_num_str += *it;
			}
		}

		else if (!flag_backslash && !flag_bracket_open) {
			if (*it == '\\') flag_backslash = true;
			else if (*it == '*') {
				vecSectionsPattern[vecSectionsPattern.size() - 1].min_length = 0;
				vecSectionsPattern[vecSectionsPattern.size() - 1].max_length = 32;
			}
			else if (*it == '{') {
				flag_bracket_open = true;
				first_num = true;
			}
			else if ((*it >= '0' && *it <= '9') || (*it >= 'a' && *it <= 'z') || (*it >= 'A' && *it <= 'Z')) {
				sectionPattern section{ 1,1,*it };
				vecSectionsPattern.push_back(section);
			}
			else if (*it == '?') {
				sectionPattern section{ 1,1,ANY_CHAR };
				vecSectionsPattern.push_back(section);
			}
			else {
				std::cout << "Pattern \"" << pattern << "\" is not valid pattern." << std::endl;
				std::cout << "*******************************************************************************************" << std::endl << std::endl;
				exit(1);
			}
		}

		else {
			std::cout << "Pattern \"" << pattern << "\" is not valid pattern." << std::endl;
			std::cout << "*******************************************************************************************" << std::endl << std::endl;
			exit(1);
		}
	}

	return vecSectionsPattern;
}

bool isBasePattern(std::string pattern, std::vector<char>& vecPattern) {
	bool flag_backslash = false;

	for (std::string::iterator it = pattern.begin(); it != pattern.end(); ++it) {
		if (flag_backslash) {
			if (*it == 'A') vecPattern.push_back(UPPER_CASE);
			else if (*it == 'a') vecPattern.push_back(LOWER_CASE);
			else if (*it == 'd') vecPattern.push_back(DIGIT);
			else return false;

			flag_backslash = false;
		}

		else {
			if (*it == '?') vecPattern.push_back(ANY_CHAR);
			else if (*it == '\\') flag_backslash = true;
			else if ((*it >= '0' && *it <= '9') || (*it >= 'a' && *it <= 'z') || (*it >= 'A' && *it <= 'Z')) vecPattern.push_back(*it);
			else return false;
		}
	}

	return true;
}

void printSearchInfo(std::string inputHash, bool flag_salt, std::string salt, bool flag_dict, bool flag_pattern, std::string pattern, bool flag_multithread) {

	std::cout << "Searching for password for hash " << inputHash << " starting..." << std::endl;

	std::cout << "Initial parameters: " << std::endl;
	
	std::cout << "Dictionary checking: ";
	if (flag_dict) std::cout << "Enabled" << std::endl;
	else std::cout << "Disabled" << std::endl;

	std::cout << "Salt: ";
	if (flag_salt) std::cout << "Enabled with salt \"" << salt << "\"" << std::endl;
	else std::cout << "Disabled" << std::endl;

	std::cout << "Pattern: ";
	if (flag_pattern) std::cout << "Enabled with pattern \"" << pattern << "\"" << std::endl;
	else std::cout << "Disabled" << std::endl;

	std::cout << "Multithreading: ";
	if (flag_multithread) std::cout << "Enabled" << std::endl;
	else std::cout << "Disabled" << std::endl;

	std::cout << std::endl;
}

void findPassword(std::string inputHash, bool flag_input, std::ifstream &input, bool flag_salt, std::string salt, bool flag_dict, 	
	std::ifstream &dictionary, bool flag_pattern, std::string pattern, bool flag_multithread) {

	std::vector<char> vecPattern;
	std::vector<sectionPattern> vecSectionsPattern;

	bool base_pattern = false;
	
	if (flag_pattern) {
		base_pattern = isBasePattern(pattern, vecPattern);

		if (!base_pattern) {
			vecSectionsPattern = parseExtendedPattern(pattern);
		}
	}

	if (flag_input) {
		while (std::getline(input, inputHash)) {
			inputHash = convertInputHash(inputHash);
			
			if (!checkInputHash(inputHash)) {
				std::cout << "Hash \"" << inputHash << "\" is not valid SHA1 hash." << std::endl;
				exit(1);
			}

			printSearchInfo(inputHash, flag_salt, salt, flag_dict, flag_pattern, pattern, flag_multithread);

			if (!flag_dict) {
				if (base_pattern) {
					bool passwordFound = false;
					std::chrono::time_point<std::chrono::system_clock> time = std::chrono::system_clock::now();
					generateBasePattern(static_cast<int>(vecPattern.size()), "", inputHash, flag_salt, salt, vecPattern, passwordFound,
						flag_multithread, time);
				}
				
				else if (flag_pattern && !base_pattern) {
					generateExtendedPattern(vecSectionsPattern, inputHash, flag_salt, salt, flag_multithread);
				}
				
				else bruteForce(inputHash, flag_salt, salt, flag_multithread);
			}

			else {
				if (!checkDictionary(inputHash, dictionary, flag_salt, salt)) {
					if (flag_pattern) std::cout << "Dictionary checked without succes. Proceeding to pattern search... " << std::endl << std::endl;
					else std::cout << "Dictionary checked without succes. Proceeding to brute force search... " << std::endl << std::endl;
					
					if (base_pattern) {
						bool passwordFound = false;
						std::chrono::time_point<std::chrono::system_clock> time = std::chrono::system_clock::now();
						generateBasePattern(static_cast<int>(vecPattern.size()), "", inputHash, flag_salt, salt, vecPattern, passwordFound,
							flag_multithread, time);
					}
					else if (flag_pattern && !base_pattern) {
						generateExtendedPattern(vecSectionsPattern, inputHash, flag_salt, salt, flag_multithread);
					}

					else bruteForce(inputHash, flag_salt, salt, flag_multithread);
				}
			}
		}
	}

	else {
		printSearchInfo(inputHash, flag_salt, salt, flag_dict, flag_pattern, pattern, flag_multithread);

		if (!flag_dict) {
			if (base_pattern) {
				bool passwordFound = false;
				std::chrono::time_point<std::chrono::system_clock> time = std::chrono::system_clock::now();
				generateBasePattern(static_cast<int>(vecPattern.size()), "", inputHash, flag_salt, salt, vecPattern, passwordFound,
					flag_multithread, time);
			}
			else if (flag_pattern && !base_pattern) {
				generateExtendedPattern(vecSectionsPattern, inputHash, flag_salt, salt, flag_multithread);
			}

			else bruteForce(inputHash, flag_salt, salt, flag_multithread);
		}

		else {
			if (!checkDictionary(inputHash, dictionary, flag_salt, salt)) {
				if (flag_pattern) std::cout << "Dictionary checked without succes. Proceeding to pattern search... " << std::endl << std::endl;
				else std::cout << "Dictionary checked without succes. Proceeding to brute force search... " << std::endl << std::endl;

				if (base_pattern) {
					bool passwordFound = false;
					std::chrono::time_point<std::chrono::system_clock> time = std::chrono::system_clock::now();
					generateBasePattern(static_cast<int>(vecPattern.size()), "", inputHash, flag_salt, salt, vecPattern, passwordFound,
						flag_multithread, time);
				}
				else if (flag_pattern && !base_pattern) {
					generateExtendedPattern(vecSectionsPattern, inputHash, flag_salt, salt, flag_multithread);
				}

				else bruteForce(inputHash, flag_salt, salt, flag_multithread);
			}
		}
	}
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		std::cout << "Invalid parameters\n";
		return 1;
	}

	//declaring program variables
	bool flag_salt = false;
	bool flag_inputFile = false;
	bool flag_pattern = false;
	bool flag_dict = false;
	bool flag_multiThread = false;
	
	std::string inputHash = "";
	std::ifstream input;
	std::ifstream dictionary;
	std::string salt = "";
	std::string pattern = "";

	//reading program arguments
	for (int i = 1; i < argc; i++) {
		if (argc == 2) {
			inputHash = argv[i];
			inputHash = convertInputHash(inputHash);

			if (!checkInputHash(inputHash)) {
				std::cout << "Hash \"" << inputHash << "\" is not valid SHA1 hash." << std::endl;
				return 1;
			}
		}

		else {
			std::string argument(argv[i]);
			if (argument.compare("-I") == 0 || argument.compare("--input") == 0) {
				if (i + 1 >= argc) {
					std::cout << "Missing input file path\n";
					return 1;
				}
				input.open(argv[++i]);
				if (!input.is_open()) {
					std::cout << "Cannot open input file\n";
					return 1;
				}
				flag_inputFile = true;
			}

			else if (argument.compare("-S") == 0 || argument.compare("--salt") == 0) {
				if (i + 1 >= argc) {
					std::cout << "Missing salt\n";
					return 1;
				}
				salt = argv[++i];
				flag_salt = true;
			}

			else if (argument.compare("-P") == 0 || argument.compare("--pattern") == 0) {
				if (i + 1 >= argc) {
					std::cout << "Missing pattern\n";
					return 1;
				}
				pattern = argv[++i];
				flag_pattern = true;
			}

			else if (argument.compare("-D") == 0 || argument.compare("--dictionary") == 0) {
				if (i + 1 >= argc) {
					std::cout << "Missing dictionary file path\n";
					return 1;
				}
				dictionary.open(argv[++i]);
				if (!dictionary.is_open()) {
					std::cout << "Cannot open dictionary file\n";
					return 1;
				}
				flag_dict = true;
			}

			else if (argument.compare("-MT") == 0) {
				flag_multiThread = true;
			}

			else {
				if (inputHash == "") {
					inputHash = argv[i];
					if (!checkInputHash(inputHash)) {
						std::cout << "Hash \"" << inputHash << "\" is not valid SHA1 hash." << std::endl;
						return 1;
					}
				}
				else {
					std::cout << "Invalid parameters\n";
					return 1;
				}
			}
		}
	}

	findPassword(inputHash, flag_inputFile, input, flag_salt, salt, flag_dict, dictionary, flag_pattern, pattern, flag_multiThread);
 
	return 0;
}
