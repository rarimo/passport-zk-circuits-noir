Circuit for quering TD3 documents(Passports)

Example input
{
  "dg1": [255, 254, 253...], // 93 bytes, DG1 in be representation  
  "eventID": "304358862882731539112827930982999386691702727710421481944329166126417129570",  
  "eventData": "1217571210886365587192326979343136122389414675532",  
  "idStateRoot": "5904469035765435216409767735512782299719282306270684213646687525744667841608",  
  "idStateSiblings": [  
    "3407986854548047084674816477222999918010365460020671033967657162352688012776",  
    "0",  
    "0",  
    ...  
    "0",  
    "0",  
  ], // Sparse Merkle tree (identity state tree), depth = 80  
  "pkPassportHash": "158067046276207(hidden)9045233186516590845",  
  "selector": "39",  
  "skIdentity": "59433543291003015964215(hidden)50571872045447542665233394",  
  "timestamp": "1713436475",  
  "currentDate": "0x323430383230",  
  "identityCounter": "0",  
  "timestampLowerbound": "0",  
  "timestampUpperbound": "0",  
  "identityCounterLowerbound": "1",  
  "identityCounterUpperbound": "0",  
  "birthDateLowerbound": "0x303030303030",  
  "birthDateUpperbound": "0x303030303030",  
  "expirationDateLowerbound": "0x303030303030",  
  "expirationDateUpperbound": "0x303030303030",  
  "citizenshipMask": "0"  
}    
Selector is 18 bit number, each bit used for reveling some part of information: if bit is 1, this field will be revealed, otherwise it will be zero.  

QUERY SELECTOR:  
0 - nullifier  
1 - birth date  
2 - expiration date  
3 - name  
4 - nationality  
5 - citizenship  
6 - sex  
7 - document number  
8 - timestamp lowerbound  
9 - timestamp upperbound  
10 - identity counter lowerbound  
11 - identity counter upperbound  
12 - passport expiration lowerbound  
13 - passport expiration upperbound  
14 - birth date lowerbound  
15 - birth date upperbound  
16 - verify citizenship mask as a whitelist
17 - verify citizenship mask as a blacklist

Passport encoding time is UTF-8 "YYMMDD"
Timestamps has 2 times of encoding:
- standard (UNIX) timestamp, like 1716482295 (UT - UNIX timestamp)
- passport timestamp, like UTF-8 "010203" -> 0x303130323033 -> 52987820126259 (PT - passport timestamp)
- Use 0x303030303030 for zero time in circuits, even if u don`t use it in selector.  

Example output:  
[  
 "20925303098627062266630214635967906856225360340756326562498326001746719100911", // 0 - nullifier
 "52992115355956", // 1 - birthDate  
 "55216908480563", // 2 - expirationDate  
 "0", // 3 - name  
 "0", // 4 - nameResidual  
 "0", // 5 - nationality  
 "5589842", // 6 - citizenship  
 "0", // 7 - sex  
 "0", // 8 - documentNumber  
 "304358862882731539112827930982999386691702727710421481944329166126417129570", // 9 - eventID  
 "1217571210886365587192326979343136122389414675532", // 10 - eventData  
 "5904469035765435216409767735512782299719282306270684213646687525744667841608", // 11 - idStateRoot  
 "39", // 12 - selector  
 "52983525027888", // 13 - currentDate  
 "0", // 14 - timestampLowerbound  
 "0", // 15 - timestampUpperbound  
 "1", // 16 - identityCounterLowerbound  
 "0", // 17 - identityCounterUpperbound  
 "52983525027888", // 18 - birthDateLowerbound  
 "52983525027888", // 19 - birthDateUpperbound  
 "52983525027888", // 20 - expirationDateLowerbound  
 "5298352502788", // 21 - expirationDateUpperbound  
 "0" // 22 - citizenshipMask  
]  