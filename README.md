<a name="readme-top"></a>

<!-- [![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
 -->


<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/othneildrew/Best-README-Template">
    <img src="images/logo.jpg" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">PeerLock - Decentralized Key Sharing Layer</h3>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

![Main Idea Screen Shots][product-screenshot1]
![Main Idea Screen Shots][product-screenshot2]
![Main Idea Screen Shots][product-screenshot3]

PeerLock is a groundbreaking decentralized access control layer designed specifically for IPFS (InterPlanetary File System) and Filecoin. Unlike traditional access control layers that rely on distributed networks and key sharding, PeerLock introduces a novel approach using Vault Providers (VP) nodes to enhance the security and efficiency of access control.

At its core, PeerLock leverages VP nodes, which are dedicated nodes that provide storage services for storing access conditions and data. When a VP node is initialized, it creates a smart contract within the Filecoin Virtual Machine (FVM). This contract acts as a secure and immutable ledger to enforce access control rules and facilitate interactions with users.

To utilize the storage services of a VP node, users are required to deposit funds into the FVM. This deposit serves as a guarantee for accessing and utilizing the VP node's storage resources. By utilizing the FVM and its smart contract capabilities, PeerLock ensures transparency, accountability, and trust in the access control process.

PeerLock's unique architecture offers several advantages over traditional access control layers. It enables efficient management of access conditions and data storage, enhancing scalability and performance. The utilization of VP nodes and the integration with the Filecoin ecosystem provide a secure and decentralized infrastructure for access control, promoting data privacy and integrity.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

It is made On top of FEVM or FVM. and For communicating with other nodes it uses libp2p. There will be two languages in it.

* Node JS(Intreacting with Blockchain)
* Go Lang(Running Nodes)


<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

To get started make sure you have installed Node JS and Go Lang in your system.

### Installation

_Below is an example of how you can instruct your audience on installing and setting up your app. This template doesn't rely on any external dependencies or services._

1. Clone the repo
   ```sh
   git clone https://github.com/Pr0fe5s0r/PeerLock
   ```
2. Install all the Go modules
   ```sh
   go get
   ```
3. Install all the NPM package.
   ```js
   cd smart/ && npm i
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

# To Run a Client Node

First Install as per the above instructions and Follow the Below Steps.

1. Init Client Node
   ```sh
   go run . -init
   ```
2. Add your Wallet Public Key and Private Key in key.json
   ```sh
   {
    address: "<YOUR_ADDRESS>",
    privateKey: "<YOUR_PRIVATEKEY>"
   }
   ```

3. Start the Client Node
   ```sh
   go run .
   ```

   Now you can access API with port :8086.
   # ENDPOINTS

   **/UploadNewData** : This will Upload New Data to VP nodes who you made Deal with.
   Request data:
   ```sh
    {
        "cid":"QmSKZq9LAJAstMUxYzuNtP1TCPtt9CsfHntWzLtqzyVVT6",
        "rec": "0x9f35C13ac826AA8ff6cfbf91CA70fDD723205DFd",
        "key": "thisisthesecrectmessage",
        "permission": false
    }
    ```

    **/AquireVault** : This will Rent Vaults from Vault Proving Nodes.

    **/RetriveKey**  : This will retrive data from VP nodes.
    Request data:
    ```sh
        {
            "cid":"QmSKZq9LAJAstMUxYzuNtP1TCPtt9CsfHntWzLtqzyVVT6",
        }
    ```

# To Run a VP Node

Same As Above Init Steps. But Just need to Deploy a VP contract.

1. Init VP Node
   ```sh
   go run . -vault-provider
   ```

Other than this you node will be a VP node.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [x] Core Concepts
- [x] Basic Functions
- [ ] Mainnet
- [ ] Secure Connection
- [ ] More Functions
- [ ] Efficient API
- [ ] Condition based Access Control

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

Your Name - [@CirrusIPFS](https://twitter.com/CirrusIPFS) - cloudipfs08@example.com

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/othneildrew/Best-README-Template.svg?style=for-the-badge
[contributors-url]: https://github.com/othneildrew/Best-README-Template/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/othneildrew/Best-README-Template.svg?style=for-the-badge
[forks-url]: https://github.com/othneildrew/Best-README-Template/network/members
[stars-shield]: https://img.shields.io/github/stars/othneildrew/Best-README-Template.svg?style=for-the-badge
[stars-url]: https://github.com/othneildrew/Best-README-Template/stargazers
[issues-shield]: https://img.shields.io/github/issues/othneildrew/Best-README-Template.svg?style=for-the-badge
[issues-url]: https://github.com/othneildrew/Best-README-Template/issues
[license-shield]: https://img.shields.io/github/license/othneildrew/Best-README-Template.svg?style=for-the-badge
[license-url]: https://github.com/othneildrew/Best-README-Template/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/othneildrew
[product-screenshot1]: images/screenshot1.png
[product-screenshot2]: images/screenshot2.png
[product-screenshot3]: images/screenshot3.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com 
