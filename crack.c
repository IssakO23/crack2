#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hash = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *hashFile = fopen(hashFilename, "r");
    if (!hashFile)
    {
        fprintf(stderr, "Error: Could not open hash file %s\n", hashFilename);
        free(hash);
        return NULL;
    }
    // Loop through the hash file, one line at a time.
    char fileHash[HASH_LEN];
    while (fgets(fileHash, sizeof(fileHash), hashFile))
    {
        // remove newline from file if hash is there
        fileHash[strcspn(fileHash, "\n")] = '\0';

        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        if (strcmp(fileHash, hash) ==0)
        {
            // If there is a match, you'll return the hash.
            fclose(hashFile);
            return hash;
        }
    }

    // If not, return NULL.
    // Before returning, do any needed cleanup:
    //   Close files?
    //   Free memory?
    fclose(hashFile);   // close file
    free(hash);         // free hash memort
    return NULL;        // no match found return null
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // Open the dictionary file for reading.
    char *hashFilename = argv[1];
    char *dictFilename = argv[2];
    FILE *dictFile = fopen(dictFilename, "r");
    if(!dictFile)
    {
        fprintf(stderr, "Error: Could not open dictionary file %s\n", dictFilename);
        exit(1);
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    int crackedCount = 0;
    char word[PASS_LEN];
    while (fgets(word, sizeof(word), dictFile))
    {
        // remove newline from the dictionary word
        word[strcspn(word, "\n")] = '\0';

        // try current word against hashes in hash file
        char *foundHash = tryWord(word, hashFilename);
        if(foundHash)
        {
            // If we got a match, display the hash and the word. For example:
            //   5d41402abc4b2a76b9719d911017c592 hello    
            printf("%s %s\n", foundHash, word);
            crackedCount++;         // increment count of cracked hashes
            free(foundHash);        // free hash returned
        }
    }

    // Close the dictionary file.
    fclose(dictFile);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked!\n", crackedCount);
    
    // Free up any malloc'd memory?
    return 0;
}

