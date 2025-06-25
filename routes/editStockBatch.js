// routes/editStockBatch.js
const express = require('express');

module.exports = function makeEditStockBatchRoutes({
  db,
  isAuthenticated,
  getCategories,
  getUnits,
  normalizeName,
  recalcProductFromBatches
}) {
  const router = express.Router();

  /* ─────────── GET /edit-stock-batch/:batchId ─────────── */
  router.get('/edit-stock-batch/:batchId', isAuthenticated, async (req, res) => {
    try {
      const { batchId } = req.params;
      const batchRef    = db.collection('stockBatches').doc(batchId);
      const batchSnap   = await batchRef.get();
      if (!batchSnap.exists)
        return res.status(404).send('Stock batch not found');
      if (batchSnap.data().accountId !== req.session.user.accountId)
        return res.status(403).send('Access denied');

      /* fetch categories & units */
      const [categories, units] = await Promise.all([
        getCategories(req.session.user.accountId),
        getUnits(req.session.user.accountId)
      ]);

      /* build a mutable batch object */
      const batchData = { id: batchSnap.id, ...batchSnap.data() };

      /* fall back to parent-product fields when missing */
      const prodSnap = await db
        .collection('products')
        .doc(batchData.productId)
        .get();

      if (prodSnap.exists) {
        const p = prodSnap.data();
        batchData.category =
          batchData.category || p.category || '';
        if (batchData.inclusiveTax === undefined &&
            p.inclusiveTax      !== undefined) {
          batchData.inclusiveTax = p.inclusiveTax;   // ★ pre-fill GST %
        }
      }

      res.render('editStockBatch', { batch: batchData, categories, units });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  /* ─────────── POST /edit-stock-batch/:batchId ─────────── */
  router.post('/edit-stock-batch/:batchId', isAuthenticated, async (req, res) => {
    try {
      const { batchId } = req.params;
      const {
        productName, purchasePrice, salePrice, quantity, inclusiveTax,
        newCategory, selectedCategory, newUnit, selectedUnit
      } = req.body;

      /* 0️⃣  permissions */
      const batchRef  = db.collection('stockBatches').doc(batchId);
      const batchSnap = await batchRef.get();
      if (!batchSnap.exists)
        return res.status(404).send('Stock batch not found');
      if (batchSnap.data().accountId !== req.session.user.accountId)
        return res.status(403).send('Access denied');

      const accountId  = req.session.user.accountId;
      const productId  = batchSnap.data().productId;
      const newName    = productName.trim();
      const newNameKey = normalizeName(newName);

      /* 1️⃣  validate & prepare numbers */
      const pp  = +parseFloat(purchasePrice);
      const sp  = +parseFloat(salePrice);
      const qty = +parseFloat(quantity);
      if (!Number.isFinite(pp)  || pp  <= 0 ||
          !Number.isFinite(sp)  || sp  <= 0 ||
          !Number.isFinite(qty) || qty <= 0)
        return res.status(400).send('Prices and quantity must be greater than zero');

      /* GST % guard (optional) */
      let taxPct = null;
      if (inclusiveTax && inclusiveTax.toString().trim() !== '') {
        taxPct = +parseFloat(inclusiveTax);
        if (!Number.isFinite(taxPct) || taxPct < 0 || taxPct > 100)
          return res.status(400).send('Inclusive-Tax % must be between 0 and 100');
      }

      /* 2️⃣  category */
      const catInput = newCategory?.trim() || selectedCategory || '';
      let category = catInput.replace(/\s+/g, ' ').trim();
      if (category)
        category = category[0].toUpperCase() + category.slice(1).toLowerCase();

      if (newCategory?.trim()) {
        const dup = (await getCategories(accountId))
          .some(c => normalizeName(c) === normalizeName(category));
        if (dup) return res.status(400).send('Category already exists — choose a different name.');
      }

      /* 3️⃣  unit */
      const unitInput = newUnit?.trim() || selectedUnit || '';
      let unit = unitInput.replace(/\s+/g, ' ').trim().toLowerCase();

      if (newUnit?.trim()) {
        const dup = (await getUnits(accountId))
          .some(u => normalizeName(u) === normalizeName(unit));
        if (dup) return res.status(400).send('Unit already exists — choose a different name.');
      }

      /* 4️⃣  adjust previously-sold units safely */
      const oldQty    = batchSnap.data().quantity          || 0;
      const oldRemain = batchSnap.data().remainingQuantity ?? oldQty;
      const deltaQty  = qty - oldQty;
      const newRemain = Math.max(0, +(oldRemain + deltaQty).toFixed(3));

      await batchRef.update({
        productName      : newName,
        purchasePrice    : pp,
        salePrice        : sp,
        quantity         : qty,
        remainingQuantity: newRemain,
        profitMargin     : +(sp - pp).toFixed(2),
        ...(unit     && { unit }),
        ...(category && { category }),
        updatedAt        : new Date()
      });

      /* 5️⃣  merge duplicate products if name clashes */
      const dupSnap = await db.collection('products')
        .where('accountId','==',accountId)
        .where('nameKey','==',newNameKey)
        .limit(1).get();

      let targetProdId = productId;
      if (!dupSnap.empty && dupSnap.docs[0].id !== productId) {
        const keeperId = dupSnap.docs[0].id;

        /* migrate batches */
        const moveOps = db.batch();
        const list = await db.collection('stockBatches')
          .where('productId','==',productId).get();
        list.docs.forEach(d => moveOps.update(d.ref, { productId: keeperId }));
        await moveOps.commit();

        /* drop orphaned product document */
        await db.collection('products').doc(productId).delete();
        targetProdId = keeperId;
      }

      /* 6️⃣  update / merge keeper product */
      await db.collection('products').doc(targetProdId).set({
        productName : newName,
        nameKey     : newNameKey,
        ...(unit      && { unit }),
        ...(category  && { category }),
        ...(taxPct !== null && { inclusiveTax: taxPct }),
        updatedAt   : new Date()
      }, { merge:true });

      /* 7️⃣  recalc quantities & profit */
      await recalcProductFromBatches(targetProdId);

      res.redirect('/view-products');
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  return router;
};
