
package x509

import (
	_ "crypto/sha256"
	_ "crypto/sha512"
	"testing"
	"fmt"
	"os"
	"bufio"
	"encoding/base64"
	"log"
	"encoding/asn1"
)


func Test(t *testing.T) {
	fileHandle, _ := os.Open("FirstTwoKLogForTesting.txt")
	defer fileHandle.Close()
	fileScanner := bufio.NewScanner(fileHandle)
	var lineCount int = 0
	for fileScanner.Scan() {
		var line = fileScanner.Text()
		if len(line) == 0{
			continue
		}
		var start_pos, end_pos, comma_count int = 0, 0, 0
		//var precert bool = true
		for i,_ := range line {
			if start_pos == 0 && (comma_count == 5 || comma_count == 7) {
				start_pos = i;
			}
			if end_pos == 0 && (comma_count == 6 || comma_count == 8)  {
				end_pos = i-1;
			}
			if start_pos > 0 && end_pos > 0 {
				if start_pos + 1 < end_pos {
					//if comma_count == 6 {
						//precert = false;
					//}
					break;
				} else {
				start_pos = 0;
				end_pos = 0;
				}
			}
			if (line[i] == ',') {
				comma_count += 1;
			}
		}
		var rawCertBytes string = line[start_pos:end_pos]
		s, _ := base64.StdEncoding.DecodeString(rawCertBytes)
		var tempC certificate
		_, err := asn1.Unmarshal(s, &tempC)
		if err != nil {
			//fmt.Print(err)
			continue
		}
		c, err := ParseCertificate(s)
		if err != nil {
			log.Fatal(err)
		} else {
			fmt.Print(c.PolicyMappings)
			fmt.Print(c.PolicyConstraints)
			fmt.Print(c.FreshestCRL)
		}

		lineCount += 1
		//fmt.Print(lineCount)
		if lineCount > 2000 {
			fmt.Print(lineCount)
			return
		}
	}

	return
}






