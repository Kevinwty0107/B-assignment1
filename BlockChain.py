import json
import logging
from typing import List
from hashlib import sha256 as H
from Transaction import *
from Block import *


logging.basicConfig(filename='main.log', filemode='w', level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("my-logger")
logger.handlers = []

class BlockChain:
    #TODO: should implement a tree?
    def __init__(self):
        """
        Constructor for the `Blockchain` class.
        """
        logger.info("Initilizing BlockChain....")
        self.chain : List[blockLinkedNode] = None
        self.chain.append(genesisBlock)
        logger.info('Initilizing done!')

    @staticmethod
    def createGenesisBlock(self):
        genesisTx = self.__getGenesisTx(self)
        genesisPrev = H(b'genesis prev').hexdigest()
        genesisNonce = 0
        genesisPOW = H(b'genesis POW').hexdigest()

        genesisBlock = Block(genesisTx, genesisPrev, genesisNonce, genesisPOW)
        
        # self.chain.append(self.genesisBlock)
        logger.info('Genesis Block has been created successfully!')
        return genesisBlock
    
    def __getGenesisTx(self):
        with open("./transactions/genesisTx.json") as f:
            jsonObj = json.load(f)
        genesisTx = Transaction(jsonObj=jsonObj[0])

        return genesisTx

    @property
    def last_block(self):
        return self.chain[-1]

    def addBlock(self, newBlockNode):
        """
        A function that adds the block to the chain after verification (proof is valid and 
        previous_hash match with the hash of last block).
        """
        txBroadcastList = []
        oldTailBlockNode = self.last_block
        self.chain.append(newBlockLinkedNode)
        if newBlockNode.height > self.oldTailBlockNode.height and newBlockNode.prevBlockNode != oldTailBlockNode:
            tempNode = oldTailBlockNode
            forkingNode = self.__retrieveForking(oldTailBlockNode, newBlockNode)
            while tempNode != forkingNode:
                txBroadcastList.append(tempNode.curBlockNode.tx)
                tempNode = tempNode.prevBlockNode
        return txBroadcastList


    def __retrieveForking(self, node1: blockLinkedNode, node2: blockLinkedNode):
        n1 = node1
        n2 = node2

        if not n1 or not p2:
            return None
        while n1 != n2:
            n1 = n1.prevBlockNode
            n2 = n2.prevBlockNode
            if n1 == n2:
                return n1
            if not n1:
                n1 = node2
            if not n2:
                n2 = node1
        return n1

        




