#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.logger import get_logger

def main():
    # On instancie un logger nommé "TEST_PG"
    logger = get_logger("TEST_PG")
    
    # On émet quelques messages à différents niveaux
    logger.debug("Message DEBUG – ne devrait pas apparaître si level=INFO")
    logger.info("Message INFO de test vers PostgreSQL et fichiers")
    logger.warning("Message WARNING de test")
    logger.error("Message ERROR de test")

if __name__ == "__main__":
    main()

