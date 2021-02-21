from Block import *
from Transaction import *
from typing import List
from hashlib import sha256
from queue import Queue
from BlockChain import *

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

    def verifyTranscation(self, tx : Transaction):
        return None

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
