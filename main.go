package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"

	//"math/big"

	random "math/rand"
	"net/http"
	"os"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-core/routing"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	tls "github.com/libp2p/go-libp2p/p2p/security/tls"

	"github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"

	// "github.com/libp2p/go-libp2p-core/peerstore"
	peer "github.com/libp2p/go-libp2p-core/peer"
	kadht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/muxer/mplex"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	"github.com/multiformats/go-multiaddr"
	ma "github.com/multiformats/go-multiaddr"
)

var (
	chost host.Host
)

const (
	topicCirrus = "cirrus-hash-sharing"
	topicIPFS   = "cirrus-ipfs-sharing"
)

const storageLimitFile = "storage_limit.json"
const dataJSON = "data.json"

var limit storageLimit

type storageLimit struct {
	SLimit int64 `json:"slimit"`
	ULimit int64 `json:"ulimit"`
}

type KeyPair struct {
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	PortNumber    int    `json:"main_port"`
	FVMPublicKey  string `json:"address"`
	FVMPrivateKey string `json:"privateKey"`
}

type VPContract struct {
	ContractAddress string `json:"contract"`
	TransactionHash string `json:"transaction"`
}

// type discoveryNotifee struct {
// 	h   host.Host
// 	ctx context.Context
// }

type PinnedObject struct {
	Hash string `json:"hash"`
}

type Data struct {
	Hash      string
	PeerID    string
	MultiAddr []string
}

type JDATA struct {
	Array []Data `json:"array"`
}

type BootstrapAddress struct {
	Address string `json:"address"`
}

type Request struct {
	ctx   context.Context
	ps    *pubsub.PubSub
	topic *pubsub.Topic
	sub   *pubsub.Subscription

	Message string
	Self    peer.ID
}

type Response struct {
	Contract string
	ID       string
	Selfddr  []string
	SelfID   peer.ID
}

type User struct {
	Address    string `json:"address"`
	Permission bool   `json:"permission"`
	Key        string `json:"key"`
}

type Vault struct {
	CID   string `json:"CID"`
	Users []User `json:"Users"`
}

type SendData struct {
	SignedValue string
	Nonce       string
	CID         string
	Contract    string
	Key         string
	VaultID     string
	Rec         string
	Permission  bool
}

type ReturnData struct {
	Peers []string `json:"Peers"`
	CID   string   `json:"CID"`
	Onwer string   `json:"owner"`
}

func checkNodeStatus(nodeUrl string) error {
	resp, err := http.Post(nodeUrl+"/api/v0/id", "", io.MultiReader())
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Node at %s is not accessible", nodeUrl)
	}

	return nil
}

func ReadBootstrapAddressFromFile(filename string) ([]BootstrapAddress, error) {
	// Read the contents of the file into a byte slice
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Unmarshal the contents of the file into a slice of BootstrapAddress structs
	var addresses []BootstrapAddress
	if err := json.Unmarshal(contents, &addresses); err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	return addresses, nil
}

func StartHTTPSever(ctx context.Context, topic *pubsub.Topic, host host.Host) {
	http.HandleFunc("/UploadNewData", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(users)
		case http.MethodPost:
			var user UploadNex
			err := json.NewDecoder(r.Body).Decode(&user)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			usrkey := user.Key
			usrCID := user.CID
			usrRec := user.Recipient
			usrPer := user.Permission

			fmt.Println(usrkey, usrCID, usrRec)
			if usrCID == "" || usrkey == "" || usrRec == "" {
				res := map[string]interface{}{
					"msg": "Sorry this is a wrong with IPFS hash",
				}
				json.NewEncoder(w).Encode(res)
			} else {

				// rres := map[string]interface{}{
				// 	"msg": "Sent the message",
				// 	"CID": usrCID,
				// 	"Rec": usrRec,
				// 	"Key": usrkey,
				// }

				wres := map[string]interface{}{
					"msg": "Something Went Wrong.",
					"CID": usrCID,
					"Rec": usrRec,
					"Key": usrkey,
				}

				nonce, err := GenerateRandomNumberString()
				if err != nil {
					json.NewEncoder(w).Encode(err)
					break
				}

				data, err := SignAValue(nonce)

				fmt.Println(data)
				baseEncode := UploadNewKey(ctx, host, data, nonce, usrRec, usrCID, usrkey, usrPer)
				if err != nil {
					json.NewEncoder(w).Encode(wres)
				} else {
					json.NewEncoder(w).Encode(baseEncode)
				}
				break
			}
			//AquireVaultToStore(ctx, host)
			break
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/RetriveKey", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(users)
		case http.MethodPost:
			var user UploadNex
			err := json.NewDecoder(r.Body).Decode(&user)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			usrCID := user.CID

			fmt.Println(usrCID)
			if usrCID == "" {
				res := map[string]interface{}{
					"msg": "Sorry this is a wrong with IPFS hash",
				}
				json.NewEncoder(w).Encode(res)
			} else {

				// rres := map[string]interface{}{
				// 	"msg": "Sent the message",
				// 	"CID": usrCID,
				// 	"Rec": usrRec,
				// 	"Key": usrkey,
				// }

				wres := map[string]interface{}{
					"msg": "Something Went Wrong.",
					"CID": usrCID,
				}

				nonce, err := GenerateRandomNumberString()
				if err != nil {
					json.NewEncoder(w).Encode(err)
					break
				}

				data, err := SignAValue(nonce)

				alldata, err := DecryptData(usrCID)

				fmt.Println(alldata.Peers, data, nonce, alldata.CID)
				RetriveKey(ctx, host, alldata.Peers, data, nonce, alldata.CID, alldata.Onwer)
				if err != nil {
					json.NewEncoder(w).Encode(wres)
				} else {
					json.NewEncoder(w).Encode(200)
				}
				break
			}
			//AquireVaultToStore(ctx, host)
			break
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/AquireVault", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(users)
		case http.MethodPost:
			AquireVaultToStore(ctx, host)
			json.NewEncoder(w).Encode(200)
			break
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	fmt.Println("Server is running on http://localhost:8086")
	errf := http.ListenAndServe(":8086", nil)
	if errf != nil {
		fmt.Println(errf)
	}
}

func main() {
	help := flag.Bool("help", false, "Display Help")
	init := flag.Bool("init", false, "Will create a new pairof Keys")
	init_vp := flag.Bool("vault-provider", false, "will create a Vault Provider Contract in FVM(Calibration)")
	cfg := parseFlags()

	if *help {
		os.Exit(0)
	} else if *init {
		GenerateLibp2pKeyPair()
	} else if *init_vp {
		vpdata, err := ioutil.ReadFile("vp.json")
		if err != nil {
			fmt.Errorf("failed to read key.json file: %s", err)
		}

		keydata, err := ioutil.ReadFile("key.json")
		if err != nil {
			fmt.Errorf("failed to read key.json file: %s", err)
		}

		Vp := VPContract{}
		Key := KeyPair{}
		err = json.Unmarshal(vpdata, &Vp)
		err = json.Unmarshal(keydata, &Key)
		if err != nil {
			fmt.Errorf("failed to parse key.json file: %s", err)
		}

		if Vp.ContractAddress == "" && Vp.TransactionHash == "" {
			fmt.Println("Deploying the Contract............")

			if Key.FVMPrivateKey == "" {
				fmt.Println("Please Give your Private Key..........")
				os.Exit(0)
			}

			contract, transaction, err := DeployVaultContract()
			if err != nil {
				fmt.Println(err.Error())
			}

			Vp.ContractAddress = contract
			Vp.TransactionHash = transaction

			fmt.Println("You are a VP now. Your Contract Info: ")
			fmt.Println("Contract Address: ", contract)
			fmt.Println("Owner:", Key.FVMPublicKey)

			VPContract, err := json.MarshalIndent(Vp, "", "  ")
			if err != nil {
				fmt.Println(err)
			}

			err = ioutil.WriteFile("vp.json", VPContract, 0644)
			if err != nil {
				fmt.Println(err)
			}
		} else {
			fmt.Println("You are already a Provider:")
			fmt.Println("Contract:", Vp.ContractAddress)
		}
		os.Exit(0)
	}
	//err := checkNodeStatus("http://127.0.0.1:5001")

	// if err != nil {
	// 	fmt.Println("Please run your IPFS node")
	// 	os.Exit(0)
	// }

	fmt.Println("Node is accessible")
	//shell := ipfs.NewShell("http://127.0.0.1:5001")
	//node, err := shell.ID()

	// if err != nil {
	// 	fmt.Println("Sry Node Hash not set")
	// 	return
	// }
	// fmt.Println("\n***************************This is the IPFS node INfo:*************************")
	// for _, addr := range node.Addresses {
	// 	fmt.Println(addr)
	// }

	fmt.Printf("[*] Listening on: %s with port: %d\n", cfg.listenHost, cfg.listenPort)

	ctx := context.Background()
	//r := rand.Reader
	prikey, port, err := ReadPrivateKey()

	// Creates a new RSA key pair for this host.
	// prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	// if err != nil {
	// 	panic(err)
	// }

	// 0.0.0.0 will listen on any interface device.
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", "0.0.0.0", port))
	transports := libp2p.ChainOptions(
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(websocket.New),
	)

	muxers := libp2p.ChainOptions(
		libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport),
	)

	security := libp2p.Security(tls.ID, tls.New)

	// libp2p.New constructs a new libp2p Host.
	// Other options can be added here.
	var dhtt *kadht.IpfsDHT
	newDHT := func(h host.Host) (routing.PeerRouting, error) {
		var err error
		dhtt, err = kadht.New(ctx, h)
		return dhtt, err
	}
	routing := libp2p.Routing(newDHT)
	chost, err := libp2p.New(
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prikey),
		transports,
		muxers,
		security,
		routing,
	)

	if err != nil {
		panic(err)
	}

	ps, err := pubsub.NewGossipSub(ctx, chost)
	if err != nil {
		panic(err)
	}

	topic, err := ps.Join(topicCirrus)
	ipfstopic, err := ps.Join(topicIPFS)
	if err != nil {
		panic(err)
	}

	addresses, err := ReadBootstrapAddressFromFile("bootstrap_addresses.json")
	if err != nil {
		fmt.Println("please do cirrus-cli init", err)
		return
	}

	fmt.Println("Bootstrap Addresses:")
	for _, address := range addresses {
		arrinfo, err := peer.AddrInfoFromString(address.Address)
		if err != nil {
			fmt.Println(err)
		}
		if err := chost.Connect(ctx, *arrinfo); err != nil {
			fmt.Println("Connection failed:", err)
			continue
		}

		fmt.Println("Connected to:", arrinfo.ID)
	}
	// Set a function as stream handler.
	// This function is called when a peer initiates a connection and starts a stream with this peer.
	//host.SetStreamHandler(protocol.ID(cfg.ProtocolID), handleStream)
	go StartHTTPSever(ctx, topic, chost)
	//go initialCheck(chost, ctx)
	fmt.Printf("\n[*] Your Multiaddress Is: /ip4/%s/tcp/%v/p2p/%s\n", cfg.listenHost, port, chost.ID().Pretty())
	peerChan := initMDNS(chost, "CIRRUS-DISCOVERY")

	for _, address := range addresses {
		arrinfo, err := peer.AddrInfoFromString(address.Address)
		if err != nil {
			fmt.Println(err)
			break
		}
		if err := chost.Connect(ctx, *arrinfo); err != nil {
			fmt.Println("Connection failed:", err)
			break
		}

		fmt.Println("Connected to:", arrinfo.ID)
	}

	SendRequestForVault(ctx, chost)

	// Bootstrap the DHT.
	// if err = dht.Bootstrap(context.Background()); err != nil {
	// 	fmt.Println("Failed to bootstrap DHT:", err)
	// 	return
	// }
	go func() {

		ticker := time.NewTicker(time.Minute)
		for {
			select {
			case <-ticker.C:
				for _, address := range addresses {
					arrinfo, err := peer.AddrInfoFromString(address.Address)
					if err != nil {
						fmt.Println(err)
						break
					}
					if err := chost.Connect(ctx, *arrinfo); err != nil {
						fmt.Println("Connection failed:", err)
						break
					}

					fmt.Println("Connected to:", arrinfo.ID)
				}

				SendRequestForVault(ctx, chost)
			}
		}
	}()

	chost.SetStreamHandler(requestVault, func(s network.Stream) {
		isVault, peer := ReadRequestVault(ctx, s)

		if isVault == true {
			if _, err := chost.Peerstore().SupportsProtocols(peer, responseVault); err == nil {
				ns, err := chost.NewStream(ctx, peer, responseVault)
				defer func() {
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
					}
				}()

				if err != nil {
					fmt.Println(err)
				}

				ID, contract, err := GetNextVaultID()

				var selfAddresses []string
				addrs := chost.Addrs()
				for _, addr := range addrs {
					selfAddresses = append(selfAddresses, addr.String())
				}

				m := Response{
					Contract: contract,
					ID:       ID,
					Selfddr:  selfAddresses,
					SelfID:   chost.ID(),
				}
				msgBytes, err := json.Marshal(m)

				err = chatSend(string(msgBytes), ns)
			}
		}
	})

	chost.SetStreamHandler(responseVault, func(stream network.Stream) {
		data, err := ResponseForVault(ctx, stream)

		response := Response{}
		err = json.Unmarshal([]byte(data), &response)
		if err != nil {
			fmt.Errorf("failed to parse key.json file: %s", err)
		}

		// VaultData, err := json.MarshalIndent(Response, "", "  ")
		// if err != nil {
		// 	fmt.Println(err)
		// }

		err = updateVPFile(response, "vp.json")
		if err != nil {
			fmt.Println("Error updating VP file:", err)
		} else {
			fmt.Println("VP file updated successfully.")
		}
	})

	chost.SetStreamHandler(sendData, func(stream network.Stream) {
		contract, CID, nonce, signedvalue, vaultID, key, rec, permission := SendDataR(ctx, stream)

		fmt.Println(contract, CID, nonce, signedvalue, vaultID, key, rec)

		addre, err := GetAddressFrom(nonce, signedvalue)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(addre, vaultID)
		owner, err := GetOwnerOFVault(contract, vaultID)

		if addre == owner {
			err = UpdatePermission(owner+".json", CID, rec, key, permission)
			if err != nil {
				fmt.Println(err)
			}
		} else {
			fmt.Println("Malicious Actor Call")
		}
	})

	chost.SetStreamHandler(retrieveData, func(stream network.Stream) {
		CID, nonce, signedValue, owner := RetrivalRequest(ctx, stream)

		addre, err := GetAddressFrom(nonce, signedValue)
		if err != nil {
			fmt.Println(err)
		}

		istrue, err := CheckWalletPermission(CID, addre, owner)

		fmt.Println(istrue)
		if istrue {
			fmt.Println(addre, "Is Requsting The Key")
		}
	})

	chost.SetStreamHandler("/cirrus/1.0.0", func(stream network.Stream) {
		//fmt.Println("New incoming stream opened")
		// Read the message from the stream.
		message, err := bufio.NewReader(stream).ReadString('\n')
		if err != nil {
			fmt.Println("Failed to read message from stream:", err)
			return
		}

		fmt.Printf("Pinning and Verifying Hash: %s", message)
		pinIPFSHash(message)
	})

	//notifee := &discoveryNotifee{h: chost, ctx: ctx}
	routingDiscovery := drouting.NewRoutingDiscovery(dhtt)

	dutil.Advertise(ctx, routingDiscovery, string("/cirrus/1.0.0"))
	peers, err := dutil.FindPeers(ctx, routingDiscovery, string("/cirrus/1.0.1"))
	if err != nil {
		panic(err)
	}

	for _, peer := range peers {
		fmt.Println(peer.ID)
	}

	//ticker := time.NewTicker(time.Second * 10)
	for { // allows multiple peers to join
		peers := <-peerChan // will block untill we discover a peer
		fmt.Println("Found peer:", peers.ID)
		if err := chost.Connect(ctx, peers); err != nil {
			fmt.Println("Connection failed:", err)
			continue
		}

		fmt.Println("Connected to:", peers.ID)
		// go streamConsoleTo(ctx, topic)
		go printMessagesFrom(ctx, topic, chost)
		go printIPFSHash(ctx, ipfstopic, chost)
		//RandomPeers(chost)
		// // open a stream, this stream will be handled by handleStream other end
		// stream, err := chost.NewStream(ctx, peer.ID, protocol.ID(cfg.ProtocolID))
		// handleStream(stream)
		// if err != nil {
		// 	fmt.Println("Stream open failed", err)
		// } else {
		// 	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

		// 	go writeData(rw)
		// 	go readData(rw)
		// 	fmt.Println("Connected to:", peer)
		// }
	}

}

func CheckWalletPermission(cid string, address string, owner string) (bool, error) {
	data, err := ioutil.ReadFile(owner + ".json")
	if err != nil {
		return false, err
	}

	var wallets []Vault
	err = json.Unmarshal(data, &wallets)
	if err != nil {
		return false, err
	}

	for _, wallet := range wallets {
		if wallet.CID == cid {
			for _, user := range wallet.Users {
				if user.Address == address {
					return user.Permission, nil
				}
			}
		}
	}

	return false, nil
}

func GetAddressFromSignature(message string, signature []byte) (common.Address, error) {
	hash := ecrypto.Keccak256Hash([]byte(message))
	sigPublicKey, err := ecrypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}

	var address common.Address
	fmt.Println(sigPublicKey)

	address.SetBytes(sigPublicKey[1:])

	return address, nil
}

func updateVPFile(response Response, filename string) error {
	// Check if the file exists
	_, err := os.Stat(filename)
	fileExists := !os.IsNotExist(err)

	var existingResponses []Response

	if fileExists {
		// Read the existing JSON data
		existingData, err := ioutil.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("failed to read file: %v", err)
		}

		// Parse the existing JSON data into a slice of Response structs
		err = json.Unmarshal(existingData, &existingResponses)
		if err != nil {
			return fmt.Errorf("failed to parse JSON: %v", err)
		}
	}

	// Check for duplicate contract address or selfID
	for _, existingResponse := range existingResponses {
		if existingResponse.Contract == response.Contract {
			existingResponse.ID = response.ID
			existingResponse.SelfID = response.SelfID
			return fmt.Errorf("duplicate contract address: %s", response.Contract)
		}
		if existingResponse.SelfID == response.SelfID {
			existingResponse.ID = response.ID
			existingResponse.SelfID = response.SelfID
			return fmt.Errorf("duplicate selfID: %s", response.SelfID)
		}
	}

	// Append the new response to the existing slice
	existingResponses = append(existingResponses, response)

	// Convert the updated data to JSON
	updatedData, err := json.MarshalIndent(existingResponses, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Write the updated JSON to the file
	err = ioutil.WriteFile(filename, updatedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}

func UpdatePermission(inputFile string, CID string, address string, key string, permission bool) error {
	var vaults []Vault

	// Check if the input file exists
	_, err := os.Stat(inputFile)
	fileExists := !os.IsNotExist(err)

	if fileExists {
		// Read JSON data from the existing file
		jsonData, err := ioutil.ReadFile(inputFile)
		if err != nil {
			return err
		}

		err = json.Unmarshal(jsonData, &vaults)
		if err != nil {
			return err
		}
	}

	// Check if a matching CID exists in the vaults
	for i := range vaults {
		if vaults[i].CID == CID {
			// Check if the user already exists for the given address
			for j := range vaults[i].Users {
				if vaults[i].Users[j].Address == address {
					// Update the permission of the existing user
					vaults[i].Users[j].Permission = permission
					vaults[i].Users[j].Key = key
					// Write the updated JSON data to the file
					updatedJSON, err := json.MarshalIndent(vaults, "", "  ")
					if err != nil {
						return err
					}
					err = ioutil.WriteFile(inputFile, updatedJSON, 0644)
					if err != nil {
						return err
					}
					return nil
				}
			}

			// If the user does not exist, add a new user to the Users array
			newUser := User{
				Address:    address,
				Permission: permission,
				Key:        key,
			}
			vaults[i].Users = append(vaults[i].Users, newUser)
			// Write the updated JSON data to the file
			updatedJSON, err := json.MarshalIndent(vaults, "", "  ")
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(inputFile, updatedJSON, 0644)
			if err != nil {
				return err
			}
			return nil
		}
	}

	// If the CID does not exist, create a new Vault with the given CID and user
	newVault := Vault{
		CID: CID,
		Users: []User{
			{
				Address:    address,
				Permission: permission,
				Key:        key,
			},
		},
	}
	vaults = append(vaults, newVault)

	// Write the updated JSON data to the file
	updatedJSON, err := json.MarshalIndent(vaults, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(inputFile, updatedJSON, 0644)
	if err != nil {
		return err
	}

	return nil
}

func SendRequestForVault(ctx context.Context, host host.Host) {
	for _, peer := range host.Network().Peers() {
		if _, err := host.Peerstore().SupportsProtocols(peer, requestVault); err == nil {
			s, err := host.NewStream(ctx, peer, requestVault)
			defer func() {
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}()
			if err != nil {
				continue
			}

			m := Request{
				Self:    host.ID(),
				Message: "This is a request for a vault",
			}
			msgBytes, err := json.Marshal(m)

			err = chatSend(string(msgBytes), s)

			//RequestForVaults(chost, peer)
		}
	}
}

func AquireVaultToStore(ctx context.Context, host host.Host) {

	vpdata, err := ioutil.ReadFile("vp.json")
	if err != nil {
		fmt.Println("failed to read key.json file:", err)
	}

	responses := []Response{}
	err = json.Unmarshal([]byte(vpdata), &responses)
	if err != nil {
		fmt.Println("failed to parse JSON: ", err)
	}

	j := 2
	for i, resp := range responses {
		// Convert the string multiaddresses to libp2p multiaddrs
		peerID, err := peer.IDFromBytes([]byte(resp.SelfID))
		if err != nil {
			fmt.Printf("failed to convert multiaddresses: %v", err)
			continue
		}

		// Connect to the peer
		err = host.Connect(context.Background(), peer.AddrInfo{
			ID: peerID,
		})
		if err != nil {
			fmt.Println("failed to connect to peer", peerID, err)
			continue
		}

		fmt.Println("Renting The Vault from", resp.Contract)

		id, cONTRACT, isaquired, err := AquireVault(resp.Contract)

		fmt.Println("ID:", id, "\n", "Contract:", cONTRACT, "\n", "Is Aquired", isaquired)

		var response Response

		response.ID = id
		response.Contract = cONTRACT
		response.SelfID = resp.SelfID

		updateVPFile(response, "aquiredVp.json")

		if i == j {
			break
		}
		// Connect to each multiaddr
		// for _, maddr := range maddrs {
		// 	// Create a peer.ID from the multiaddr
		// 	peerID, err := peer.AddrInfoFromP2pAddr(maddr)
		// 	if err != nil {
		// 		fmt.Println("failed to extract peer ID: %v", err)
		// 		continue
		// 	}
		// }
	}
}

func UploadNewKey(ctx context.Context, host host.Host, signValue string, nonce string, recipient string, CID string, key string, permission bool) string {

	vpdata, err := ioutil.ReadFile("aquiredVp.json")
	if err != nil {
		fmt.Println("failed to read key.json file:", err)
	}

	var peers []string

	responses := []Response{}
	err = json.Unmarshal([]byte(vpdata), &responses)
	if err != nil {
		fmt.Println("failed to parse JSON: ", err)
	}

	for _, resp := range responses {
		// Convert the string multiaddresses to libp2p multiaddrs
		peerID, err := peer.IDFromBytes([]byte(resp.SelfID))
		if err != nil {
			fmt.Printf("failed to convert multiaddresses: %v", err)
			continue
		}

		// Connect to the peer
		err = host.Connect(context.Background(), peer.AddrInfo{
			ID: peerID,
		})
		if err != nil {
			fmt.Println("failed to connect to peer", peerID, err)
			continue
		}

		if _, err := host.Peerstore().SupportsProtocols(peerID, sendData); err == nil {
			ns, err := host.NewStream(ctx, peerID, sendData)
			defer func() {
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}()

			peers = append(peers, peer.Encode(peerID))
			if err != nil {
				fmt.Println(err)
			}

			var selfAddresses []string
			addrs := host.Addrs()
			for _, addr := range addrs {
				selfAddresses = append(selfAddresses, addr.String())
			}

			fmt.Println("Sending Data to", resp.SelfID, resp.Contract)

			fmt.Println(nonce, signValue)

			m := SendData{
				SignedValue: signValue,
				CID:         CID,
				Contract:    resp.Contract,
				Key:         key,
				Nonce:       nonce,
				VaultID:     resp.ID,
				Rec:         recipient,
				Permission:  permission,
			}
			msgBytes, err := json.Marshal(m)

			err = chatSend(string(msgBytes), ns)
		}
		// Connect to each multiaddr
		// for _, maddr := range maddrs {
		// 	// Create a peer.ID from the multiaddr
		// 	peerID, err := peer.AddrInfoFromP2pAddr(maddr)
		// 	if err != nil {
		// 		fmt.Println("failed to extract peer ID: %v", err)
		// 		continue
		// 	}
		// }
	}

	fileData, err := ioutil.ReadFile("key.json")
	if err != nil {
		fmt.Println("failed to read key.json file: %s", err)
	}

	keyPair := KeyPair{}
	err = json.Unmarshal(fileData, &keyPair)
	if err != nil {
		fmt.Println("failed to parse key.json file: %s", err)
	}

	encryptedData, err := EncryptData(peers, CID, keyPair.FVMPublicKey)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return ""
	}

	return encryptedData
}

func RetriveKey(ctx context.Context, host host.Host, PeerList []string, signValue string, nonce string, CID string, owner string) {

	for _, resp := range PeerList {
		fmt.Println(resp)
		// Convert the string multiaddresses to libp2p multiaddrs
		peerID, err := peer.Decode(resp)
		if err != nil {
			fmt.Printf("failed to convert multiaddresses: %v", err)
			continue
		}

		// Connect to the peer
		err = host.Connect(context.Background(), peer.AddrInfo{
			ID: peerID,
		})
		if err != nil {
			fmt.Println("failed to connect to peer", peerID, err)
			continue
		}

		fileData, err := ioutil.ReadFile("key.json")
		if err != nil {
			fmt.Println("failed to read key.json file: %s", err)
		}

		keyPair := KeyPair{}
		err = json.Unmarshal(fileData, &keyPair)
		if err != nil {
			fmt.Println("failed to parse key.json file: %s", err)
		}

		if _, err := host.Peerstore().SupportsProtocols(peerID, retrieveData); err == nil {
			ns, err := host.NewStream(ctx, peerID, retrieveData)
			defer func() {
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}()

			var selfAddresses []string
			addrs := host.Addrs()
			for _, addr := range addrs {
				selfAddresses = append(selfAddresses, addr.String())
			}

			fmt.Println(nonce, signValue)

			m := SendData{
				SignedValue: signValue,
				CID:         CID,
				Nonce:       nonce,
				Rec:         owner,
			}
			msgBytes, err := json.Marshal(m)

			err = chatSend(string(msgBytes), ns)
		}
		// Connect to each multiaddr
		// for _, maddr := range maddrs {
		// 	// Create a peer.ID from the multiaddr
		// 	peerID, err := peer.AddrInfoFromP2pAddr(maddr)
		// 	if err != nil {
		// 		fmt.Println("failed to extract peer ID: %v", err)
		// 		continue
		// 	}
		// }
	}
}

func EncryptData(peers []string, cid string, owner string) (string, error) {
	data := ReturnData{
		Peers: peers,
		CID:   cid,
		Onwer: owner,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encryptedData := base64.StdEncoding.EncodeToString(jsonData)
	return encryptedData, nil
}

func DecryptData(encryptedData string) (*ReturnData, error) {
	jsonData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	var data ReturnData
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func convertToMultiaddrs(addrs []string) ([]ma.Multiaddr, error) {
	maddrs := make([]ma.Multiaddr, len(addrs))
	for i, addr := range addrs {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse multiaddress: %v", err)
		}
		maddrs[i] = maddr
	}
	fmt.Println("\n\n", maddrs)
	return maddrs, nil
}

func GetIPAddress(maddrStr string) (string, error) {
	maddr, err := ma.NewMultiaddr(maddrStr)
	if err != nil {
		return "", err
	}

	ipByte, errs := maddr.ValueForProtocol(ma.P_IP4)

	if len(ipByte) == 0 {
		return "", fmt.Errorf("multiaddress %s does not contain an IP address", errs)
	}

	return ipByte, nil
}

func sendStream(host host.Host, peerID peer.ID, hash string) (bool, error) {
	// Connect to the target node
	err := host.Connect(context.Background(), peer.AddrInfo{ID: peerID})
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		return false, nil
	}

	// Open a new stream to the target node
	stream, err := host.NewStream(context.Background(), peerID, protocol.ID("/cirrus-ipfs/pinhash"))
	if err != nil {
		fmt.Println("Error opening stream:", err)
		return false, nil
	}

	// Write the message to the stream
	_, err = stream.Write([]byte(hash))
	if err != nil {
		fmt.Println("Error writing to stream:", err)
		return false, nil
	}

	// Close the stream
	err = stream.Close()
	if err != nil {
		fmt.Println("Error closing stream:", err)
		return false, nil
	}

	return true, err
}

func verifyStream(host host.Host, peerID peer.ID, hash string) {
	// Connect to the target node
	err := host.Connect(context.Background(), peer.AddrInfo{ID: peerID})
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		return
	}

	// Open a new stream to the target node
	stream, err := host.NewStream(context.Background(), peerID, requestVault)
	if err != nil {
		fmt.Println("Error opening stream:", err)
		return
	}

	// Write the message to the stream
	_, err = stream.Write([]byte(hash))
	if err != nil {
		fmt.Println("Error writing to stream:", err)
		return
	}
}

func RequestForVaults(host host.Host, peerID peer.ID) {
	// Connect to the target node
	err := host.Connect(context.Background(), peer.AddrInfo{ID: peerID})
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		return
	}

	// Open a new stream to the target node
	stream, err := host.NewStream(context.Background(), peerID, requestVault)
	if err != nil {
		fmt.Println("Error opening stream:", err)
		return
	}

	// Write the message to the stream
	err = chatSend(chost.ID().String(), stream)

	// Close the stream
	// err = stream.Close()
	if err != nil {
		fmt.Println("Error closing stream:", err)
		return
	}
}

func printStreamMessage(stream network.Stream) {
	buffer := make([]byte, 1024)
	n, err := stream.Read(buffer)
	if err != nil {
		fmt.Println(err)
		return
	}

	message := string(buffer[:n])
	fmt.Println("Received IPFS hash:", message)
	pinIPFSHash(message)
}

func checkIfPinned(hash string) bool {
	// Make a request to the IPFS HTTP API to retrieve the list of pinned objects
	resp, err := http.Get("http://localhost:5001/api/v0/pin/ls")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read the response body into a byte slice
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// Unmarshal the JSON response into a slice of PinnedObject structs
	var pinnedObjects []PinnedObject
	if err := json.Unmarshal(body, &pinnedObjects); err != nil {
		panic(err)
	}

	// Iterate over the slice of PinnedObject structs and check if the hash is pinned
	for _, obj := range pinnedObjects {
		if obj.Hash == hash {
			return true
		}
	}

	return false
}

func ReadDataJSON(hash string) string {
	file, err := os.OpenFile(dataJSON, os.O_RDONLY, 0644)
	if err != nil {
		fmt.Println("Error: Unale to Open the file")
		return "not"
	}
	defer file.Close()

	var data []Data
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		fmt.Println("Error decoding JSON data:", err)
		return "not"
	}

	for _, d := range data {
		if d.Hash == hash {
			return "not"
		}
	}
	return ""
}

func GetJSONData() []Response {
	file, err := os.OpenFile("vpdata.json", os.O_RDONLY, 0644)
	if err != nil {
		return nil
	}
	defer file.Close()

	var data []Response
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		fmt.Println("GetJSONdata Error decoding JSON data:", err)
		return nil
	}

	// for _, d := range data {
	// 	if d.Hash == hash {
	// 		return ""
	// 	}
	// }
	return data
}

func streamConsoleTo(ctx context.Context, topic *pubsub.Topic, hash string, host host.Host) string {

	random.Seed(time.Now().UnixNano())
	peers := host.Peerstore().PeersWithAddrs()
	// for _, peerInfo := range peers {
	// 	if peerInfo.ID == peerID {
	// 		fmt.Println("Multiaddress of the connected node:", peerInfo.Addrs[0].String())
	// 		break
	// 	}
	// }
	if len(peers) == 0 {
		fmt.Println("No connected peers.")
	}
	//fmt.Println(rand.Int())
	randomPeer := peers[random.Intn(len(peers))]
	for host.ID().Pretty() == randomPeer.Pretty() {
		nrandomPeer := peers[random.Intn(len(peers))]
		randomPeer = nrandomPeer
	}

	npeerID := randomPeer
	//go verifyStream(host, npeerID, "Hello. this is a request")
	// err := host.Connect(context.Background(), peer.AddrInfo{ID: npeerID})
	// if err != nil {
	// 	fmt.Println("Error connecting to peer trying:", err)
	// 	streamConsoleTo(ctx, topic, hash, host, isRe)
	// 	return ""
	// }

	allpeers := host.Network().Peers()
	var mul []ma.Multiaddr
	for _, peer := range allpeers {
		if npeerID.Pretty() == peer.Pretty() {
			addrs := host.Network().Peerstore().Addrs(peer)
			mul = addrs
			break
		}
	}

	stringAddrs := make([]string, len(mul))
	for i, multiAddr := range mul {
		stringAddrs[i] = multiAddr.String()
	}

	for {
		rw, _ := startPeerAndConnect(host, npeerID, hash)
		if rw == nil {
			fmt.Println("Unable to Send the Hash")
		}
		fmt.Println("Message Sent:", hash)

		// for _, d := range storedData {
		// 	if d.PeerID == npeerID.Pretty() && len(allpeers) > 0 {
		// 		fmt.Println("Same Peer")
		// 		streamConsoleTo(ctx, topic, hash, host, isRe)
		// 		break
		// 	}
		// }

		return ""
	}
}

func printMessagesFrom(ctx context.Context, topic *pubsub.Topic, chost host.Host) {

	// if _, err := os.Stat(storageLimitFile); os.IsNotExist(err) {
	// 	// If the file does not exist, create it and set the storage limit to 100 MB
	// 	limit = storageLimit{
	// 		ULimit: 1024 * 1024 * 500,
	// 		SLimit: 1024 * 1024 * 500,
	// 	}
	// 	file, err := os.Create(storageLimitFile)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	// 	defer file.Close()
	// 	json.NewEncoder(file).Encode(limit)
	// 	file.Close()
	// 	os.Chmod(storageLimitFile, 0400)
	// } else {
	// 	// If the file exists, read the storage limit from it
	// 	file, err := os.Open(storageLimitFile)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	// 	defer file.Close()
	// 	json.NewDecoder(file).Decode(&limit)
	// }

	sub, err := topic.Subscribe()
	if err != nil {
		panic(err)
	}
	for {
		m, err := sub.Next(ctx)
		if err != nil {
			panic(err)
		}
		thispeer := chost.ID().Pretty()
		if thispeer == m.ReceivedFrom.String() {
			continue
		} else {
			fmt.Println(m.ReceivedFrom, ": ", string(m.Message.Data))
			// newShel := ipfs.NewShell("http://localhost:5001")
			// data, err := newShel.Cat(string(m.Message.Data))
			// if err != nil {
			// 	fmt.Println("Error: Unable to reach the hash")
			// }
			// if data != nil {
			// 	fmt.Println("IPFS hash is Pinned")
			// }
		}
	}
}

func printIPFSHash(ctx context.Context, topic *pubsub.Topic, chost host.Host) {

	// if _, err := os.Stat(storageLimitFile); os.IsNotExist(err) {
	// 	// If the file does not exist, create it and set the storage limit to 100 MB
	// 	limit = storageLimit{
	// 		ULimit: 1024 * 1024 * 500,
	// 		SLimit: 1024 * 1024 * 500,
	// 	}
	// 	file, err := os.Create(storageLimitFile)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	// 	defer file.Close()
	// 	json.NewEncoder(file).Encode(limit)
	// 	file.Close()
	// 	os.Chmod(storageLimitFile, 0400)
	// } else {
	// 	// If the file exists, read the storage limit from it
	// 	file, err := os.Open(storageLimitFile)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	// 	defer file.Close()
	// 	json.NewDecoder(file).Decode(&limit)
	// }

	sub, err := topic.Subscribe()
	if err != nil {
		panic(err)
	}
	for {
		m, err := sub.Next(ctx)
		if err != nil {
			panic(err)
		}
		thispeer := chost.ID().Pretty()
		if thispeer == m.ReceivedFrom.String() {
			continue
		} else {
			fmt.Println(m.ReceivedFrom, ": ", string(m.Message.Data))
			// newShel := ipfs.NewShell("http://localhost:5001")
			// data, err := newShel.Cat(string(m.Message.Data))
			// if err != nil {
			// 	fmt.Println("Error: Unable to reach the hash")
			// }
			// if data != nil {
			// 	fmt.Println("IPFS hash is Pinned")
			// }
		}
	}
}

func pinIPFSHash(hash string) {
	fmt.Println(hash)
}

// func checkCirrusNode(h host.Host, ctx context.Context) bool {

// 	data := GetJSONData()

// 	for _, d := range data {
// 		pid := ping.NewPingService(h)

// 		peerID, err := peer.Decode(d.PeerID)
// 		if err != nil {
// 			fmt.Println(err)
// 		}

// 		fmt.Println(peerID)
// 		fmt.Println("Checking if node with peer ID", peerID, "is active")

// 		pinger := pid.Ping(ctx, peerID)
// 		select {
// 		case <-pinger:
// 			fmt.Println(d.PeerID, "Node is active")
// 		case <-time.After(time.Second * 5):
// 			fmt.Println(d.PeerID, "Node is not active")
// 		}
// 	}

// 	return true
// }

func ReadPrivateKey() (crypto.PrivKey, int, error) {
	fileData, err := ioutil.ReadFile("key.json")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read key.json file: %s", err)
	}

	keyPair := KeyPair{}
	err = json.Unmarshal(fileData, &keyPair)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse key.json file: %s", err)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(keyPair.PrivateKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode private key: %s", err)
	}

	privKey, err := crypto.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal private key: %s", err)
	}

	return privKey, keyPair.PortNumber, nil
}

func GenerateLibp2pKeyPair() (string, string, error) {

	privKey, pubKey, err1 := crypto.GenerateEd25519Key(rand.Reader)
	if err1 != nil {
		return "", "", err1
	}

	skbytes, _ := crypto.MarshalPrivateKey(privKey)

	id, _ := peer.IDFromPublicKey(pubKey)

	StringPrivateKey := base64.StdEncoding.EncodeToString(skbytes)

	StringPublicKey := id.Pretty()

	keyPair := KeyPair{
		PrivateKey: StringPrivateKey,
		PublicKey:  StringPublicKey,
		PortNumber: 9999,
	}

	keyPairJSON, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		return "", "", err
	}

	err = ioutil.WriteFile("key.json", keyPairJSON, 0644)
	if err != nil {
		return "", "", err
	}

	fmt.Printf("New Private Key: %s\n", StringPrivateKey)
	fmt.Printf("New Public Key: %s\n", StringPublicKey)
	return StringPublicKey, StringPrivateKey, nil
}

func GenerateRandomNumberString() (string, error) {
	random.Seed(time.Now().UnixNano())

	// Generate a random number between 0 and 99999
	randomNumber := random.Intn(100000)

	// Format the number as a 5-digit string
	randomNumberString := fmt.Sprintf("%05d", randomNumber)

	return randomNumberString, nil
}

// zeroBytes clears a byte slice to prevent it from lingering in memory
func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
