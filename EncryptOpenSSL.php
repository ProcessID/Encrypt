<?php
   // Chiffrement/Déchiffrement avec OpenSSL
   // Compatible avec chiffre_chaine() et dechiffre_chaine() de WD
   // Les clef doivent être préalablement générées avec:
   // $key_aes256 = base64_encode(openssl_random_pseudo_bytes(32));
   // $key_hash512 = base64_encode(openssl_random_pseudo_bytes(64));
   // Les données ($data) doivent être en UTF8
   // -------------------
   // -- Instanciation --
   // -------------------
   // $obj = new EncryptOpenSSL($key_aes256, $key_hash512, $methode);
   // $key_aes256 = <key aes256>
   // $key_hash512 = <key hash512>
   // $methode = <'aes-256-cbc' | ...>
   
   
   namespace ProcessID\Encrypt;
   
   class EncryptOpenSSL {
      private $_key_aes256;
      private $_key_hash512;
      private $_methode;
      
      function __construct($key_aes256, $key_hash512, $methode) {
         $this->SetKey_aes256($key_aes256);
         $this->SetKey_hash512($key_hash512);
         $this->SetMethode($methode);
      }
      
      function SetKey_aes256($key_aes256) {
         $this->_key_aes256 = $key_aes256;
      }
     
      function SetKey_hash512($key_hash512) {
         $this->_key_hash512 = $key_hash512;
      }
      
      function SetMethode($methode) {
         $this->_methode = $methode;
      }
      
      private function key_aes256() {
         return $this->_key_aes256;
      }
      
      private function key_hash512() {
         return $this->_key_hash512;
      }
      
      private function methode() {
         return $this->_methode;
      }
      
      function encrypt_string($data) {
         $key_aes256 = base64_decode($this->key_aes256());
         $key_hash512 = base64_decode($this->key_hash512());
         
         $iv_length = openssl_cipher_iv_length($this->methode());
         $iv = openssl_random_pseudo_bytes($iv_length);

         // À la place de '1', il faudrait utiliser la constante OPENSSL_RAW_DATA qui vaut 1, mais elle n'existe pas en PHP 5.3 où il fallait passer 'true', donc la valeur 1 est parfaite pour toutes les versions
         $first_encrypted = openssl_encrypt($data, $this->methode(), $key_aes256, 1, $iv);
         $second_encrypted = hash_hmac('sha512', $first_encrypted, $key_hash512, TRUE);

         $output = base64_encode($iv.$second_encrypted.$first_encrypted);
         
         return $output;
      }
      
      function decrypt_string($data) {
         $key_aes256 = base64_decode($this->key_aes256());
         $key_hash512 = base64_decode($this->key_hash512());
         $mix = base64_decode($data);
         
         $iv_length = openssl_cipher_iv_length($this->methode());

         $iv = substr($mix,0,$iv_length);
         $second_encrypted = substr($mix, $iv_length, 64);
         $first_encrypted = substr($mix, $iv_length+64);

         // À la place de '1', il faudrait utiliser la constante OPENSSL_RAW_DATA qui vaut 1, mais elle n'existe pas en PHP 5.3 où il fallait passer 'true', donc la valeur 1 est parfaite pour toutes les versions
         $data = openssl_decrypt($first_encrypted, $this->methode(), $key_aes256, 1, $iv);
         $second_encrypted_new = hash_hmac('sha512', $first_encrypted, $key_hash512, TRUE);

         // La fonction hash_equals() n'existe qu'à partir de PHP 5.6
         if (function_exists('hash_equals')) {
            if (hash_equals($second_encrypted, $second_encrypted_new)) {
               return $data;
            }
            return false;
         } else {
            if ($second_encrypted == $second_encrypted_new) {
               return $data;
            }
            return false;
         }  
      }
      
      static function generate_key_aes256() {
         return base64_encode(openssl_random_pseudo_bytes(32));
      }
      
      static function generate_key_hash512() {
         return base64_encode(openssl_random_pseudo_bytes(64));
      }
      
   }
?>
