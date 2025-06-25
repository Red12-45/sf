// routes/addProduct.js
module.exports = function makeAddProductRoutes({
  db,
  isAuthenticated,
  restrictRoute,
  getCategories,
  getUnits,
  normalizeName
}) {
  const express = require('express');
  const router  = express.Router();

  // GET /add-product – render form
  router.get(
    '/add-product',
    isAuthenticated,
    restrictRoute('/add-product'),
    async (req, res) => {
      try {
        const accountId     = req.session.user.accountId;
        const selectedCat   = req.query.category     || '';
        const selectedUnit  = req.query.selectedUnit || '';
        const sortOrder     = req.query.sortOrder    || 'asc';

        const [categories, units] = await Promise.all([
          getCategories(accountId),
          getUnits(accountId)
        ]);

        let q = db.collection('products')
                  .where('accountId','==',accountId);
        if (selectedCat.trim() !== '')
          q = q.where('category','==',selectedCat);
        q = q.orderBy('productName', sortOrder);

        const snap = await q.get();
        const existingProducts = snap.docs.map(d => ({
          id  : d.id,
          name: d.data().productName
        }));

        res.render('addProduct', {
          success         : req.query.success,
          errorMessage    : null,
          categories,
          units,
          existingProducts,
          selectedCategory: selectedCat,
          selectedUnit,
          sortOrder
        });
      } catch (err) {
        res.status(500).send(err.toString());
      }
    }
  );

  /* ─────────── POST /add-product – create or update ─────────── */
  router.post(
    '/add-product',
    isAuthenticated,
    restrictRoute('/add-product'),
    async (req, res) => {
      try {
        const accountId = req.session.user.accountId;
        const {
          existingProduct,
          productName    = '',
          wholesalePrice,
          retailPrice,
          quantity,
          inclusiveTax,
          selectedCategory,
          newCategory,
          selectedUnit,
          newUnit
        } = req.body;

        const wp  = +parseFloat(wholesalePrice);
        const rp  = +parseFloat(retailPrice);
        const qty = +parseFloat(quantity);

        /* GST validation */
        let taxPct = null;
        if (inclusiveTax && inclusiveTax.toString().trim() !== '') {
          taxPct = +parseFloat(inclusiveTax);
          if (!Number.isFinite(taxPct) || taxPct < 0 || taxPct > 100)
            return res.status(400).send('Inclusive-Tax % must be between 0 and 100');
        }

        if (!Number.isFinite(wp) || wp <= 0 ||
            !Number.isFinite(rp) || rp <= 0 ||
            !Number.isFinite(qty) || qty <= 0)
          return res.status(400).send('Prices and quantity must be > 0');

        /* Category handling */
        let category = newCategory?.trim()
          ? newCategory.trim()
          : (selectedCategory || '');
        category = category.replace(/\s+/g, ' ').trim();
        if (category)
          category = category[0].toUpperCase() + category.slice(1).toLowerCase();

        if (newCategory?.trim()) {
          const existingCats = await getCategories(accountId);
          if (existingCats.some(c => normalizeName(c) === normalizeName(category)))
            return res.status(400).send('Category already exists — choose a different name.');
        }

        /* Unit handling */
        const unitRawInput = newUnit?.trim() || selectedUnit || '';
        let unit = unitRawInput.replace(/\s+/g, ' ').trim().toLowerCase();

        if (newUnit?.trim()) {
          const existingUnits = await getUnits(accountId);
          if (existingUnits.some(u => normalizeName(u) === normalizeName(unit)))
            return res.status(400).send('Unit already exists — choose a different name.');
        }

        if (existingProduct === 'new' && !productName.trim())
          return res.status(400).send('Product name is required');

        /* Duplicate detection */
        const nameKey    = normalizeName(productName);
        let   productRef = null;
        let   productSnap= null;

        if (existingProduct && existingProduct !== 'new') {
          productRef  = db.collection('products').doc(existingProduct);
          productSnap = await productRef.get();
          if (!productSnap.exists)
            return res.status(404).send('Selected product not found');

        } else {
          const fastDup = await db.collection('products')
            .where('accountId','==',accountId)
            .where('nameKey','==',nameKey)
            .limit(1).get();

          if (!fastDup.empty) {
            productRef  = fastDup.docs[0].ref;
            productSnap = fastDup.docs[0];
          } else {
            const all = await db.collection('products')
              .where('accountId','==',accountId)
              .select('productName')
              .get();

            const legacy = all.docs.find(d =>
              normalizeName(d.data().productName) === nameKey
            );
            if (legacy) {
              await legacy.ref.update({ nameKey });
              productRef  = legacy.ref;
              productSnap = legacy;
            }
          }
        }

        /* UPDATE flow */
        if (productRef && productSnap) {
          const d    = productSnap.data();
          const curQ = d.quantity || 0;
          const newQ = curQ + qty;

          const newWholesale = +(((curQ * d.wholesalePrice) + (qty * wp)) / newQ).toFixed(2);
          const newRetail    = +(((curQ * d.retailPrice)   + (qty * rp)) / newQ).toFixed(2);

          await productRef.update({
            quantity      : newQ,
            wholesalePrice: newWholesale,
            retailPrice   : newRetail,
            profitMargin  : newRetail - newWholesale,
            updatedAt     : new Date(),
            ...(unit      && { unit }),
            ...(category  && { category }),
            ...(taxPct !== null && { inclusiveTax: taxPct })
          });

        /* CREATE flow */
        } else {
          const data = {
            productName   : productName.trim(),
            nameKey,
            wholesalePrice: wp,
            retailPrice   : rp,
            quantity      : qty,
            profitMargin  : rp - wp,
            category,
            unit,
            createdAt     : new Date(),
            accountId,
            ...(taxPct !== null && { inclusiveTax: taxPct }),

            /* legacy */
            oldestWholesale: wp,
            oldestBatchQty : qty,
            secondWholesale: null,
            oldestRetail   : rp,
            secondRetail   : null
          };
          productRef  = await db.collection('products').add(data);
          productSnap = { id: productRef.id, data: () => data };
        }

        /* Always create batch */
        await db.collection('stockBatches').add({
          productId        : productRef.id,
          productName      : productSnap.data().productName,
          purchasePrice    : wp,
          salePrice        : rp,
          quantity         : qty,
          remainingQuantity: qty,
          batchDate        : new Date(),
          accountId,
          unit
        });

        res.redirect('/add-product?success=1');
      } catch (err) {
        res.status(500).send(err.toString());
      }
    }
  );

  return router;
};
