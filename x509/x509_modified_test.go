
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
	"io"
)


func Test(t *testing.T) {
	fileHandle, _ := os.Open("/data3/ct_data/ct-log.txt")
	defer fileHandle.Close()
	r := bufio.NewReader(fileHandle)
	var lineCount int = 0
	for line, _, err := r.ReadLine(); err != io.EOF; {
		lineCount += 1
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
			if line[i] == ',' {
				comma_count += 1;
			}
		}
		var rawCertBytes string = string(line[start_pos:end_pos])
		s, _ := base64.StdEncoding.DecodeString(rawCertBytes)
		c, err := ParseCertificate(s)
		if err != nil {
			fmt.Print(err)
			log.Fatal(err)
		} else {
			if (len(c.PolicyMappings) > 0) {
				fmt.Print(c.PolicyMappings)
			}
			if (len(c.PolicyConstraints) > 0) {
				fmt.Print(c.PolicyConstraints)
			}
			if (len(c.FreshestCRL.fullName) > 0 || len(c.FreshestCRL.CRLIssuer) > 0) {
				fmt.Print(c.FreshestCRL)
			}
		}

		// fmt.Print(lineCount)
		if lineCount > 2000 {
			fmt.Print(lineCount)
			return
		}
	}
	return
}






