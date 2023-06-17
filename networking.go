package main

// dht "github.com/libp2p/go-libp2p-kad-dht"
// pubsub "github.com/libp2p/go-libp2p-pubsub"

type hash struct {
	Hash string `json:"hash"`
}

type UploadNex struct {
	Recipient  string `json:"rec"`
	CID        string `json:"cid"`
	Key        string `json:"key"`
	Permission bool   `json:"permission"`
}

var users = []hash{}

// func HttpAPIServer(ctx context.Context) error {

// 	ps, err := pubsub.NewGossipSub(ctx, chost)
// 	if err != nil {
// 		panic(err)
// 	}

// 	topic, err := ps.Join(topicCirrus)
// 	if err != nil {
// 		panic(err)
// 	}

// 	http.HandleFunc("/addPin", func(w http.ResponseWriter, r *http.Request) {
// 		switch r.Method {
// 		case http.MethodGet:
// 			w.Header().Set("Content-Type", "application/json")
// 			json.NewEncoder(w).Encode(users)
// 		case http.MethodPost:
// 			var user hash
// 			err := json.NewDecoder(r.Body).Decode(&user)
// 			if err != nil {
// 				http.Error(w, err.Error(), http.StatusBadRequest)
// 				return
// 			}
// 			usreHash := user.Hash
// 			verifyHash, verr := cid.Decode(usreHash)
// 			if verr != nil {
// 				res := map[string]interface{}{
// 					"msg": "Sorry this is a wrong with IPFS hash",
// 				}
// 				json.NewEncoder(w).Encode(res)
// 			} else {
// 				verifiedHash := verifyHash.String()

// 				rres := map[string]interface{}{
// 					"msg":  "Pinned Hash",
// 					"hash": verifiedHash,
// 				}

// 				wres := map[string]interface{}{
// 					"msg":  "Not Pinned. Something Went Wrong.",
// 					"hash": verifiedHash,
// 				}

// 				newShel := ipfs.NewShell("http://localhost:5001")
// 				err := newShel.Pin(verifiedHash)
// 				streamConsoleTo(context.Background(), topic, verifiedHash)
// 				if err != nil {
// 					json.NewEncoder(w).Encode(wres)
// 				} else {
// 					json.NewEncoder(w).Encode(rres)
// 				}

// 			}
// 		default:
// 			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
// 		}
// 	})

// 	fmt.Println("Server is running on http://localhost:8080")
// 	errw := http.ListenAndServe(":8081", nil)
// 	if errw != nil {
// 		fmt.Println(errw)
// 	}

// 	return nil
// }
