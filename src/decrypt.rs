use cipher::{
    crypto_common::{BlockSizes, InnerInit, InnerUser},
    inout::InOut,
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockModeDecBackend, BlockModeDecClosure, BlockModeDecrypt, BlockSizeUser, ParBlocks,
    ParBlocksSizeUser,
};
use core::fmt;

/// ECB mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    cipher: C,
}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockModeDecrypt for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    fn decrypt_with_backend(&mut self, f: impl BlockModeDecClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher } = self;
        cipher.decrypt_with_backend(Closure { f })
    }
}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    type Inner = C;
}

impl<C> InnerInit for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C> AlgorithmName for Decryptor<C>
where
    C: BlockCipherDecrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ecb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockCipherDecrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ecb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

struct Closure<BS, BC>
where
    BS: BlockSizes,
    BC: BlockModeDecClosure<BlockSize = BS>,
{
    f: BC,
}

impl<BS, BC> BlockSizeUser for Closure<BS, BC>
where
    BS: BlockSizes,
    BC: BlockModeDecClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BC> BlockCipherDecClosure for Closure<BS, BC>
where
    BS: BlockSizes,
    BC: BlockModeDecClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockCipherDecBackend<BlockSize = Self::BlockSize>>(self, backend: &B) {
        let Self { f } = self;
        f.call(&mut Backend { backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockSizeUser<BlockSize = BS>,
{
    backend: &'a BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockSizeUser<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    type ParBlocksSize = BK::ParBlocksSize;
}

impl<'a, BS, BK> BlockModeDecBackend for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn decrypt_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.backend.decrypt_block(block);
    }

    #[inline(always)]
    fn decrypt_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        self.backend.decrypt_par_blocks(blocks);
    }
}
