use cipher::{
    consts::U1,
    crypto_common::{BlockSizes, InnerInit, InnerUser},
    inout::InOut,
    AlgorithmName, Block, BlockBackend, BlockCipher, BlockCipherEncrypt, BlockClosure,
    BlockSizeUser, ParBlocksSizeUser,
};
use core::fmt;

/// ECB mode encryptor.
#[derive(Clone)]
pub struct Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    cipher: C,
}

impl<C> BlockSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockCipherEncrypt for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, .. } = self;
        cipher.encrypt_with_backend(Closure { f })
    }
}

impl<C> InnerUser for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    type Inner = C;
}

impl<C> InnerInit for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C> AlgorithmName for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ecb::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ecb::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

struct Closure<BS, BC>
where
    BS: BlockSizes,
    BC: BlockClosure<BlockSize = BS>,
{
    f: BC,
}

impl<BS, BC> BlockSizeUser for Closure<BS, BC>
where
    BS: BlockSizes,
    BC: BlockClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BC> BlockClosure for Closure<BS, BC>
where
    BS: BlockSizes,
    BC: BlockClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { f, .. } = self;
        f.call(&mut Backend { backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    backend: &'a mut BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<'a, BS, BK> BlockBackend for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.backend.proc_block(block);
    }
}
