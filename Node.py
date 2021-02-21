from Block import *
from Transaction import *
from typing import List
from hashlib import sha256
from BlockChain import *
import numpy as np

from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

class Node:
    def __init__(self, genesisBlock: Block = None, nodeID = None):
        self.id = nodeID
        self.miningNodeList = []
        self.blockChain = BlockChain(genesisBlock)
        self.blockQueue = Queue()
        self.globalUnverifiedTxPool : List[Transaction] = []
        self.miningDifficulty = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    
    def miningBlock(self, tx : Transaction):
        if self.verifyTranscation(tx):
            nonce = 0
            blockPOW = str(self.miningDifficulty + 1)
            #TODO: Check if prev is the pow
            prevBlockNode = self.blockChain.last_block
            prevHashing = prevBlockNode.curBlock.hashing()
            txAndPrevBeforeHash = tx.toString() + prevHashing
            while int(blockPOW, 16) > self.miningDifficulty:
                blockInfo = txAndPrevBeforeHash + str(nonce)
                blockPOW = sha256(blockInfo.encode('utf-8')).hexdigest()
                nonce += 1
            nonce -= 1

            #TODO: add to the longest chain
            newBlock = Block(tx, prevHashing, nonce, blockPOW)
            newBlockLinkedNode = BlockLinkedNode(prevBlockNode, newBlock, prevBlockNode.height + 1)
            self.broadCastBlock(newBlock)
            txBroadcastList = self.addBlockToChain(newBlockLinkedNode)
            if txBroadcastList:
                self.__broadcastTx(txBroadcastList)

    def verifyTranscation(self, tx: Transaction) :  # verify a Tx
        """
            1. Ensure the transaction is not already on the blockchain (included in an existing valid block)
            2. Ensure the transaction is validly structured
        """
        return self.verifyTxNotAlreadyOnBlockchain(tx) and self.verifyTxValidStruct(tx)

    def verifyTxNotAlreadyOnBlockchain(self, tx: Transaction):
        #  Ensure the transaction is not already on the blockchain (included in an existing valid block)
        prevBlock = self.blockChain.last_block
        while prevBlock:
            if tx.txNumber == prevBlock.curBlockNode.tx.txNumber:
                log.error("Verification Failed! Tx is already on the blockchain")
                return False
            prevBlock = prevBlock.prevBlockNode
        return True

    def verifyTxValidStruct(self, tx: Transaction):
        """
            Ensure the transaction is validly structured
        """
        TxNumHash = self.verifyTxNumberHash(tx) # number hash is correct
        TxInNum = self.verifyTxInputsNumber(tx) # each number in the input exists as a transaction already on the blockchain, each output in the input actually exists in the named transaction
        TxPKsig = self.verifyTxPubKeyAndSig(tx) # each output in the input has the same public key, and that key can verify the signature on this transaction
        TxDS = self.verifyTxDoubleSpend(tx) # that public key is the most recent recipient of that output (i.e. not a double-spend)
        TxIOSum = self.verifyTxInOutSum(tx) # the sum of the input and output values are equal
        return TxNumHash and TxInNum and TxPKsig and TxDS and TxIOSum

    def verifyTxNumberHash(self, tx: Transaction):
        #  Ensure number hash is correct
        num_Hash = tx.txNumber
        now_Hash = tx.hashingTxNumber()
        if tx.txNumber != '' and now_Hash == num_Hash:
            return True
        else:
            log.error("Node " + self.id + " :" + "Tx Verification Failed! Number hash is not correct")

    def verifyTxInputsNumber(self, tx: Transaction):
        #  each number in the input exists as a transaction already on the blockchain
        #  each output in the input actually exists in the named transaction
        validInput_count= 0
        for Input in tx.inputList:
            num_Exist = False
            outputright = False
            prevBlock = self.blockChain.last_block
            while prevBlock:
                if Input.number == prevBlock.curBlockNode.tx.txNumber: # find that old transaction in the current block
                    num_Exist = True
                    for pBlockTxOutput in prevBlock.curBlockNode.tx.outputList:
                        if Input.output.isEqual(pBlockTxOutput):  # verify the output content
                            outputright = True
                            break
                    break
                prevBlock = prevBlock.prevBlockNode
            if num_Exist and outputright:
                validInput_count += 1
        if validInput_count == len(tx.inputList):
            return True
        else:
            log.error("Node " + self.id + " :" + "Tx Verification Failed! Inputs are not correct")

    def verifyTxPubKeyAndSig(self, tx: Transaction):
        #  each output in the input has the same public key, and that key can be used to verify the signature of the transaction
        if not tx.inputList:
            return False
        sender_PublicKey: bytes = tx.inputList[0].output.pubkey
        for Input in tx.inputList:
            if Input.output.pubKey != sender_PublicKey:
                log.error("Node " + self.id + " :" + "Tx Verification Failed! Input pubKey is not unique")
                return False

        verifyKey = VerifyKey(sender_PublicKey, HexEncoder)
        try:
            verifyKey.verify(tx.sig.encode('utf-8'), encoder=HexEncoder)
            return True
        except BadSignatureError:
            log.error("Node " + self.id + " :" + "Tx Verification Failed! Signature verification failed")
            return False
    
    def verifyTxDoubleSpend(self, tx:Transaction):
        # that public key is the most recent recipient of that output (i.e. not a double-spend)
        for Input in tx.inputList:
            prevBlock = self.blockChain.last_block
            while prevBlock:
                for pBlockTxInput in prevBlock.curBlockNode.tx.inputList:
                    if Input.isEqual(pBlockTxInput)
                        log.error("Node " + self.id + " :" + "Tx Verification Failed! Double spend detected")
                        return False
                prevBlock = prevBlock.prevBlockNode
            return True

    def __verifyTxInOutSum(self, tx: Transaction) :
        #  the sum of the input and output values are equal
        inSum, outSum = 0, 0
        inSum = np.sum([x.output.value for x in tx.inputList])
        outSum = np.sum([y.value for y in tx.outputList]]
        if not inSum == outSum:
            log.error("Node " + self.id + " :" + "Tx Verification Failed! Tx Inputs val sum is not equal to outputs sum")
        return bool(inSum == outSum)

    def broadCastBlock(self, newBlock):
        for tempNode in self.miningNodeList:
            if tempNode != self:
                tempNode.blockQueue.put(newBlock)
    
    def addBlockToChain(newBlockLinkedNode : blockLinkedNode):
        self.blockChain.addBlock(newBlockLinkedNode)

    def __broadcastTx(self, txBroadcastList):
        for tempNode in self.miningNodeList:
            if tempNode != self:
                for tx in txBroadcastList:
                    tempNode.globalUnverifiedTxPool.append(tx)
    

    def writeToFile():
        return None
