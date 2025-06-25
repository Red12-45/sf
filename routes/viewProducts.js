/**
 * routes/viewProducts.js
 * ------------------------------------------------------------
 * All server endpoints that back the “View Products” page
 * (/view-products and its AJAX helpers).
 */
module.exports = function makeViewProductsRoutes({
  db,
  isAuthenticated,
  restrictRoute,
  restrictAction,
  getCategories,
  recalcProductFromBatches
}) {
  const express = require('express');
  const router  = express.Router();

  /* ─────────── GET /view-products (main page) ─────────── */
  router.get(
    '/view-products',
    isAuthenticated,
    restrictRoute('/view-products'),
    async (req, res) => {
      try {
        const accountId      = req.session.user.accountId;
        const filterCategory = req.query.filterCategory || '';
        const stockThreshold = req.query.stockThreshold || '';
        const sortOrder      = req.query.sortOrder || 'asc';

        let q = db.collection('products').where('accountId', '==', accountId);
        if (filterCategory.trim() !== '')
          q = q.where('category', '==', filterCategory);
        if (stockThreshold.trim() !== '')
          q = q.where('quantity', '<', parseInt(stockThreshold));
        q = q.orderBy('productName', sortOrder);

        const snap     = await q.get();
        const products = snap.docs.map(d => ({ id: d.id, ...d.data() }));

        /* pull batch info in chunks of 10 IDs to stay under Firestore limits */
        const productIds = products.map(p => p.id);
        const batchesMap = {};
        if (productIds.length) {
          const chunkSize = 10;
          const promises  = [];
          for (let i = 0; i < productIds.length; i += chunkSize) {
            promises.push(
              db.collection('stockBatches')
                .where('productId', 'in', productIds.slice(i, i + chunkSize))
                .get()
            );
          }
          (await Promise.all(promises)).forEach(batchSnap => {
            batchSnap.docs.forEach(doc => {
              const d   = doc.data();
              const pid = d.productId;
              if (!batchesMap[pid]) batchesMap[pid] = [];
              d.profitMargin = d.salePrice - d.purchasePrice;
              batchesMap[pid].push({ id: doc.id, ...d });
            });
          });
        }
        products.forEach(p => (p.batches = batchesMap[p.id] || []));

        const categories = await getCategories(accountId);

        res.render('viewProducts', {
          products,
          categories,
          filterCategory,
          stockThreshold,
          sortOrder,
          blockedActions: req.session.blockedActions || {},
          csrfToken     : req.csrfToken()
        });
      } catch (err) {
        res.status(500).send(err.toString());
      }
    }
  );

  /* ─────────── POST /delete-product/:productId ─────────── */
  router.post(
    '/delete-product/:productId',
    isAuthenticated,
    restrictAction('/view-products', 'delete'),
    async (req, res) => {
      try {
        const { productId } = req.params;
        const prodRef  = db.collection('products').doc(productId);
        const prodSnap = await prodRef.get();

        if (!prodSnap.exists)
          return res.status(404).send('Product not found');
        if (prodSnap.data().accountId !== req.session.user.accountId)
          return res.status(403).send('Access denied');

        /* ↓ cannot delete if stock or batches still exist */
        if (prodSnap.data().quantity > 0)
          return res.status(400).send('Cannot delete – stock still available');
        const batchCheck = await db
          .collection('stockBatches')
          .where('productId', '==', productId)
          .limit(1)
          .get();
        if (!batchCheck.empty)
          return res
            .status(400)
            .send('Cannot delete – batches still exist');

        await prodRef.delete();

        if (req.xhr) return res.json({ success: true });
        res.redirect('/view-products');
      } catch (err) {
        console.error(err);
        if (req.xhr) return res.json({ success: false, error: err.toString() });
        res.status(500).send(err.toString());
      }
    }
  );

  /* ─────────── POST /delete-stock-batch/:batchId ─────────── */
  router.post(
    '/delete-stock-batch/:batchId',
    isAuthenticated,
    restrictAction('/view-products', 'delete'),
    async (req, res) => {
      try {
        const { batchId } = req.params;
        const batchRef    = db.collection('stockBatches').doc(batchId);
        const batchDoc    = await batchRef.get();

        if (!batchDoc.exists)
          return res.status(404).send('Stock batch not found');
        if (batchDoc.data().accountId !== req.session.user.accountId)
          return res.status(403).send('Access denied');

        const productId = batchDoc.data().productId;
        await batchRef.delete();
        await recalcProductFromBatches(productId);

        if (req.xhr) {
          const prodSnap = await db
            .collection('products')
            .doc(productId)
            .get();
          const p = prodSnap.data();
          return res.json({
            success: true,
            product: {
              id            : productId,
              wholesalePrice: p.wholesalePrice,
              retailPrice   : p.retailPrice,
              quantity      : p.quantity,
              profitMargin  : p.profitMargin
            }
          });
        }
        res.redirect('/view-products');
      } catch (err) {
        console.error('Error deleting stock batch:', err);
        if (req.xhr) return res.json({ success: false, error: err.toString() });
        res.status(500).send(err.toString());
      }
    }
  );

  /* ─────────── POST /api/edit-stock-batch-field/:batchId ─────────── */
  router.post(
    '/api/edit-stock-batch-field/:batchId',
    isAuthenticated,
    restrictAction('/view-products', 'edit'),
    async (req, res) => {
      try {
        const { batchId }  = req.params;
        const { field, value } = req.body;

        const batchRef  = db.collection('stockBatches').doc(batchId);
        const batchSnap = await batchRef.get();

        if (!batchSnap.exists) throw new Error('Batch not found');
        if (batchSnap.data().accountId !== req.session.user.accountId)
          throw new Error('Access denied');

        const update = { updatedAt: new Date() };
        if (field === 'purchasePrice' || field === 'salePrice') {
          update[field] = parseFloat(value);
        } else if (field === 'quantity') {
          const qty = parseInt(value, 10);
          update.quantity          = qty;
          update.remainingQuantity = qty;
        } else {
          throw new Error('Invalid field');
        }
        await batchRef.update(update);

        const updated      = (await batchRef.get()).data();
        const profitMargin = updated.salePrice - updated.purchasePrice;
        await batchRef.update({ profitMargin });

        /* recalc & return updated product figures */
        const productId = batchSnap.data().productId;
        await recalcProductFromBatches(productId);
        const prodSnap = await db.collection('products').doc(productId).get();
        const prod     = prodSnap.data();

        res.json({
          success: true,
          batch: {
            purchasePrice     : updated.purchasePrice,
            salePrice         : updated.salePrice,
            quantity          : updated.quantity,
            remainingQuantity : updated.remainingQuantity,
            profitMargin
          },
          product: {
            id            : prodSnap.id,
            wholesalePrice: prod.wholesalePrice,
            retailPrice   : prod.retailPrice,
            quantity      : prod.quantity,
            profitMargin  : prod.profitMargin
          }
        });
      } catch (err) {
        res.json({ success: false, error: err.toString() });
      }
    }
  );

  return router;
};
