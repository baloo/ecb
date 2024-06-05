use cipher::{
    crypto_common::{BlockSizes, InnerInit, InnerUser},
    inout::InOut,
    AlgorithmName, Block, BlockBackend, BlockCipher, BlockCipherDecrypt, BlockClosure,
    BlockSizeUser, ParBlocks, ParBlocksSizeUser,
};
use core::fmt;

/// ECB mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    cipher: C,
}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockCipherDecrypt for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher } = self;
        cipher.decrypt_with_backend(Closure { f })
    }
}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    type Inner = C;
}

impl<C> InnerInit for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C> AlgorithmName for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ecb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher + AlgorithmName,
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
        let Self { f } = self;
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
    type ParBlocksSize = BK::ParBlocksSize;
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

    #[inline(always)]
    fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        self.backend.proc_par_blocks(blocks);
    }
}
