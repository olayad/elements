#!/bin/bash

## Preparations
if [ ! -e ./conference ] || [ ! -e ./src ]; then
  echo "bad diretory."
  exit 1
fi

# First we need to set up our config files to walk through this demo
# Let's have some testing user directories for elements nodes.
rm -r ~/bc2_elementsdir1 ; rm -r ~/bc2_elementsdir2
mkdir ~/bc2_elementsdir1 ; mkdir ~/bc2_elementsdir2

# Also configure the nodes by copying the configuration files from
# this directory (and read them):
cp ./conference/rpc_tutorial/elements1.conf ~/bc2_elementsdir1/elements.conf
cp ./conference/rpc_tutorial/elements2.conf ~/bc2_elementsdir2/elements.conf

# Set some aliases:
cd src
shopt -s expand_aliases

ELEMENTSPATH="."

alias e1-cli="$ELEMENTSPATH/elements-cli -datadir=$HOME/bc2_elementsdir1"
alias e1-dae="$ELEMENTSPATH/elementsd -datadir=$HOME/bc2_elementsdir1"
alias e2-cli="$ELEMENTSPATH/elements-cli -datadir=$HOME/bc2_elementsdir2"
alias e2-dae="$ELEMENTSPATH/elementsd -datadir=$HOME/bc2_elementsdir2"

# start elementsd
e1-dae
e2-dae

LDW=1
while [ "${LDW}" = "1" ]
do
  LDW=0
  e1-cli getwalletinfo > /dev/null 2>&1 || LDW=1
  e2-cli getwalletinfo > /dev/null 2>&1 || LDW=1
  if [ "${LDW}" = "1" ]; then
    echo -n -e "."
    sleep 1
  fi
done

# Prime the chain, see "immature balance" holds all funds until genesis is mature
echo ""
echo e1-cli getwalletinfo
e1-cli getwalletinfo
read -p 'チェーンの初期状態: genesisが成熟するまで"immature balance" に全ての資金が保持されます。'

# Mining for now is OP_TRUE
e1-cli generate 101

# Now we have 21M OP_TRUE value
echo e1-cli getwalletinfo
e1-cli getwalletinfo
sleep 3
echo e2-cli getwalletinfo
e2-cli getwalletinfo
read -p 'generate 101 したことで2,100万が誰でも使える(OP_TRUE)状態となりました。'

# Primed and ready

######## WALLET ###########


#Sample raw transaction RPC API

#   ~Core API

#* `getrawtransaction <txid> 1`
#* `gettransaction <txid> 1`
#* `listunspent`
#* `decoderawtransaction <hex>`
#* `sendrawtransaction <hex>`
#* `validateaddress <address>
#* `listreceivedbyaddress <minconf> <include_empty> <include_watchonly>`

#   Elements Only API

#* `blindrawtransaction <hex>`
#* `dumpblindingkey <address>`
#* `importblindingkey <addr> <blindingkey>`

# But let's start with a managed wallet example

# First, drain OP_TRUE
# read -p 'まず、それぞれに資金を掃き出します。'
# e1-cli sendtoaddress $(e1-cli getnewaddress) 10500000 "" "" true
# e1-cli generate 101
# e2-cli sendtoaddress $(e2-cli getnewaddress) 10500000 "" "" true
# e2-cli generate 101

# Funds should be evenly split
# echo e1-cli getwalletinfo
# e1-cli getwalletinfo
# echo e2-cli getwalletinfo
# e2-cli getwalletinfo
# read -p 'これで資金は分割されました。'

# Have Bob send coins to himself using a blinded Elements address!
# Blinded addresses start with `CTE`, unblinded `2`
echo 'ボブ(e2)が自分自身にElementsの.(ブラインド)アドレスを使って送金してみます。'
e2-cli help getnewaddress
read -p 'ブランドありのアドレスは`CTE`で始まり、ブラインドなしの場合は`2`で始まります。'
echo e2-cli getnewaddress
ADDR=$(e2-cli getnewaddress)
echo $ADDR

# How do we know it's blinded? Check for blinding key, unblinded address.
echo e2-cli help validateaddress
e2-cli help validateaddress
echo e2-cli validateaddress $ADDR
e2-cli validateaddress $ADDR
echo 'blinding keyとunblinded addressを確認してください。'
read -p 'ボブがこのアドレスに(ボブからボブに)送金します。'

echo e2-cli sendtoaddress $ADDR 1
TXID=$(e2-cli sendtoaddress $ADDR 1)
echo ${TXID}

e2-cli generate 1

# Now let's examine the transaction, both in wallet and without

# In-wallet, take a look at blinding information
read -p 'ボブのウォレットでブラインド情報をみてみましょう。'
echo e2-cli gettransaction $TXID
e2-cli gettransaction $TXID
# e1 doesn't have in wallet
read -p 'アリス(e1)のウォレットからは見えません。'
echo e1-cli gettransaction $TXID
e1-cli gettransaction $TXID

# public info, see blinded ranges, etc
read -p 'アリス(e1)からは公開情報(金額の範囲等)は見えます。'
echo e1-cli getrawtransaction $TXID 1
e1-cli getrawtransaction $TXID 1

# Now let's import the key to spend
read -p 'アリス(e1)に先ほどの送信先アドレスの秘密鍵をインポートします。'
echo e2-cli dumpprivkey $ADDR
E2PRV=$(e2-cli dumpprivkey $ADDR)
echo $E2PRV
echo e1-cli importprivkey $E2PRV
e1-cli importprivkey $(e2-cli dumpprivkey $ADDR)

# We can't see output value info though
read -p 'アリス(e1)のウォレットでもトランザクションが見えるようになります。'
echo e1-cli gettransaction $TXID
e1-cli gettransaction $TXID
# And it won't show in balance or known outputs
read -p 'しかし額は不明のままです。'
echo e1-cli getwalletinfo
e1-cli getwalletinfo
# Amount for transaction is unknown, so it is not shown.
read -p 'トランザクションの額がわからないのでUTXOにも現れません。'
echo e1-cli listunspent 1 1
e1-cli listunspent 1 1

# Solution: Import blinding key
read -p 'blindingkeyもインポートします。'
echo e2-cli dumpblindingkey $ADDR
DBK=$(e2-cli dumpblindingkey $ADDR)
echo $DBK
echo e1-cli importblindingkey $ADDR $DBK
e1-cli importblindingkey $ADDR $(e2-cli dumpblindingkey $ADDR)

# Check again, funds should show
read -p 'これでトランザクションの額が見えるようになりました。'
echo e1-cli getwalletinfo
e1-cli getwalletinfo
echo e1-cli listunspent 1 1
e1-cli listunspent 1 1
echo e1-cli gettransaction $TXID
e1-cli gettransaction $TXID

#Exercises
#===
# Resources: https://bitcoin.org/en/developer-documentation
#1. Find the change output in one of your transactions.
#2. Use both methods to get the total input value of the transaction.
#3. Find your UTXO with the most confirmations.
#4. Create a raw transaction that pays 0.1 coins in fees and has two change addresses.
#5. Build blinded multisig p2sh

###### ASSETS #######
read -p '###### ASSETS #######'

# Many of the RPC calls have added asset type or label 
# arguments and reveal alternative asset information. With no argument all are listed:
echo '多くのRPCコマンドにassetの引数や結果が追加されています。'
echo e1-cli help getwalletinfo
e1-cli help getwalletinfo
read -p '引数で指定されない場合は全てのアセットがリストされます。'
echo e1-cli getwalletinfo
e1-cli getwalletinfo

# Notice we now see "bitcoin" as an asset. This is the asset label for the hex for "bitcoin" which can be discovered:
read -p '"bitcoin"も1つのアセットとして見えます。'
echo e1-cli help dumpassetlabels
e1-cli help dumpassetlabels
echo e1-cli dumpassetlabels
e1-cli dumpassetlabels

# You can also filter calls using specific asset hex or labels:
echo 'アセットはラベルでも、16進数でも指定できます。'
read -p '* ラベルを指定した場合'
echo e1-cli getwalletinfo bitcoin
e1-cli getwalletinfo bitcoin
# bitcoin's hex asset type
read -p '* 16進を指定した場合'
echo e1-cli getwalletinfo 09f663de96be771f50cab5ded00256ffe63773e2eaa9a604092951cc3d7c6621
e1-cli getwalletinfo 09f663de96be771f50cab5ded00256ffe63773e2eaa9a604092951cc3d7c6621

# We can also issue our own assets, 1 asset and 1 reissuance token in this case
echo '独自のアセットも発行できます。'
echo e1-cli help issueasset
e1-cli help issueasset
read -p 'ここでは、アリスがアセットを1、再発行トークンを1として発行してみます。'
echo e1-cli issueasset 1 1
ISSUE=$(e1-cli issueasset 1 1)
echo $ISSUE
ASSET=$(echo $ISSUE | jq '.asset' | tr -d '"')

# From there you can look at the issuances you have in your wallet
echo e1-cli help listissuances
e1-cli help listissuances
echo e1-cli listissuances
read -p '発行したアセットはアリスのウォレットで見えます。'
e1-cli listissuances

# If you gave `issueasset` a 2nd argument greater than 0, you can also reissue the base asset
echo e1-cli help reissueasset
e1-cli help reissueasset
read -p 'アセットの発行時に、再発行トークンに正の値を指定しておくと、元のアセットを再発行できます。'
echo e1-cli reissueasset $ASSET 1
REISSUE=$(e1-cli reissueasset $ASSET 1)
echo $REISSUE

# or make another unblinded asset issuance, with only reissuance tokens initially
read -p 'また、アセットの発行時に、再発行トークンのみを指定したり、ブラインドしないアセットも発行できます。'
echo e1-cli issueasset 0 1 false
e1-cli issueasset 0 1 false

# Then two issuances for that particular asset will show
read -p '最初に発行したアセットを指定すると、2つの発行履歴が見えます。'
echo e1-cli listissuances $ASSET
e1-cli listissuances $ASSET

read -p 'ボブにはブラインドしないアセットの発行履歴だけが見えています。'
echo e2-cli listissuances
e2-cli listissuances

# To label the asset add this to your elements.conf file then restart your daemon:
# assetdir=$ASSET:yourlabelhere
# It really doesn't matter what you call it, labels are local things only.

# To send issued assets, add an additional argument to sendtoaddress using the hex or label
read -p 'アセットを送ってみましょう。'
echo e2-cli getnewaddress
BADDR=$(e2-cli getnewaddress)
echo $BADDR
echo e1-cli help sendtoaddress
e1-cli help sendtoaddress
echo e1-cli sendtoaddress $BADDR 1 "" "" false $ASSET
e1-cli sendtoaddress $BADDR 1 "" "" false $ASSET
echo e2-cli generate 1
e2-cli generate 1
echo e2-cli getwalletinfo $ASSET
e2-cli getwalletinfo $ASSET

# e2 doesn't know about the issuance for the transaction sending him the new asset
read -p 'ボブには、いま受信した(ブラインドする)アセットの発行履歴の額/再発行トークンは見えません。'
echo e2-cli listissuances
e2-cli listissuances

# let's import an associated address and rescan
read -p 'lets import an associated address and rescan'
TXID=$(echo $ISSUE | jq '.txid' | tr -d '"')
ADDR=$(e1-cli gettransaction $TXID | jq '.details[0].address' | tr -d '"')

e2-cli importaddress $ADDR

# e2 now sees issuance, but doesn't know amounts as they are blinded
read -p 'まだボブには(ブラインドするア)セットの発行履歴の額/再発行トークンは見えません。'
e2-cli listissuances

# We need to import the issuance blinding key. We refer to issuances by their txid/vin pair
# as there is only one per input
read -p 'isuuanceblindingkeyもインポートします。'
VIN=$(echo $ISSUE | jq '.vin' | tr -d '"')
ISSUEKEY=$(e1-cli dumpissuanceblindingkey $TXID $VIN)
echo e1-cli dumpissuanceblindingkey $TXID $VIN
echo $ISSUEKEY
echo e2-cli importissuanceblindingkey $TXID $VIN $ISSUEKEY
e2-cli importissuanceblindingkey $TXID $VIN $ISSUEKEY

# Now e2 can see issuance amounts and blinds
read -p 'これでボブにもブラインドするアセットの発行履歴の額/再発行トークンまで見えるようになりました。'
e2-cli listissuances


read -p 'これでボブにもブラインドするアセットの発行履歴の額/再発行トークンまで見えるようになりました。'
RTXID=$(echo $REISSUE | jq '.txid' | tr -d '"')
RVIN=$(echo $REISSUE | jq '.vin' | tr -d '"')
RADDR=$(e1-cli gettransaction $RTXID | jq '.details[0].address' | tr -d '"')
echo e2-cli importaddress $RADDR
e2-cli importaddress $RADDR
echo e2-cli listissuances
e2-cli listissuances
echo '再発行のトランザクションのアドレスをインポートすることで再発行の履歴が見えるようになりました。'
read -p '再発行時のisuuanceblindingkeyもインポートします。'
RISSUEKEY=$(e1-cli dumpissuanceblindingkey $RTXID $RVIN)
echo e1-cli dumpissuanceblindingkey $RTXID $RVIN
echo $RISSUEKEY
echo e2-cli importissuanceblindingkey $RTXID $RVIN $RISSUEKEY
e2-cli importissuanceblindingkey $RTXID $RVIN $RISSUEKEY
e2-cli listissuances
read -p 'これで再発行の履歴の額/assetblinderまで見えるようになりました。'



e1-cli stop
e2-cli stop
