package main

// // For debug
// func HexDump(data []byte) {
// 	for i := 0; i < len(data); i += 16 {
// 		fmt.Printf("%08x: ", i)
// 		end := min(i + 16, len(data))
// 		for j, b := range data[i:end] {
// 			if j > 0 {
// 				fmt.Print(" ")
// 			}
// 			fmt.Printf("%02x", b)
// 		}
// 		fmt.Println()
// 	}
// }
