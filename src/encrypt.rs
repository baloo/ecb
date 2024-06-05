use cipher::{
    consts::U1,
    crypto_common::{BlockSizes, InnerInit, InnerUser},
    inout::InOut,
    AlgorithmName, Block, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
    BlockModeEncBackend, BlockModeEncClosure, BlockModeEncrypt, BlockSizeUser, ParBlocksSizeUser,
};
use core::fmt;

/// ECB mode encryptor.
#[derive(Clone)]
pub struct Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    cipher: C,
}

impl<C> BlockSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockModeEncrypt for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, .. } = self;
        cipher.encrypt_with_backend(Closure { f })
    }
}

impl<C> InnerUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type Inner = C;
}

impl<C> InnerInit for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C> AlgorithmName for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ecb::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
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
    BC: BlockModeEncClosure<BlockSize = BS>,
{
    f: BC,
}

impl<BS, BC> BlockSizeUser for Closure<BS, BC>
where
    BS: BlockSizes,
    BC: BlockModeEncClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BC> BlockCipherEncClosure for Closure<BS, BC>
where
    BS: BlockSizes,
    BC: BlockModeEncClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(self, backend: &B) {
        let Self { f, .. } = self;
        f.call(&mut Backend { backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    backend: &'a BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<'a, BS, BK> BlockModeEncBackend for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn encrypt_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.backend.encrypt_block(block);
    }
}
