// routes/productDownload.js
const express = require('express');
const ExcelJS = require('exceljs');

module.exports = function makeProductDownloadRoutes({ db, isAuthenticated, restrictRoute }) {
  const router = express.Router();

  /* ─────────── DOWNLOAD PRODUCTS → EXCEL ─────────── */
  // GET /download-products
  router.get(
    '/download-products',
    isAuthenticated,
    restrictRoute('/view-products'),
    async (req, res) => {
      try {
        const accountId = req.session.user.accountId;
        const { filterCategory = '', stockThreshold = '', sortOrder = 'asc' } = req.query;

        /* 1. replicate the same Firestore query used in /view-products */
        let q = db.collection('products').where('accountId', '==', accountId);
        if (filterCategory.trim() !== '')
          q = q.where('category', '==', filterCategory);
        if (stockThreshold.trim() !== '')
          q = q.where('quantity', '<', parseFloat(stockThreshold));
        q = q.orderBy('productName', sortOrder);

        const prodSnap   = await q.get();
        const products   = prodSnap.docs.map(d => ({ id: d.id, ...d.data() }));
        const productIds = products.map(p => p.id);

        /* 2. pull batches so we can compute avg profit */
        const batchesMap = {};
        if (productIds.length) {
          const batchPromises = [];
          for (let i = 0; i < productIds.length; i += 10) {
            const slice = productIds.slice(i, i + 10);
            batchPromises.push(
              db.collection('stockBatches')
                .where('productId', 'in', slice)
                .get()
            );
          }
          const batchSnaps = await Promise.all(batchPromises);
          batchSnaps.forEach(s => {
            s.docs.forEach(b => {
              const d   = b.data();
              const pid = d.productId;
              if (!batchesMap[pid]) batchesMap[pid] = [];
              batchesMap[pid].push(d);
            });
          });
        }

        /* 3. create workbook */
        const wb = new ExcelJS.Workbook();
        const ws = wb.addWorksheet('Products');

        ws.columns = [
          { header: 'Serial',          key: 'serial',          width: 8  },
          { header: 'Product Name',    key: 'productName',     width: 30 },
          { header: 'Wholesale ₹',     key: 'wholesalePrice',  width: 14 },
          { header: 'Retail ₹',        key: 'retailPrice',     width: 12 },
          { header: 'Quantity',        key: 'quantity',        width: 10 },
          { header: 'Unit',            key: 'unit',            width: 8  },
          { header: 'Profit /Unit ₹',  key: 'profitMargin',    width: 16 },
          { header: 'Avg Profit ₹',    key: 'avgProfit',       width: 14 },
          { header: 'Category',        key: 'category',        width: 16 }
        ];

        products.forEach((p, idx) => {
          /* compute average profit exactly like the page does */
          let avgProfit = 0;
          const batches = batchesMap[p.id] || [];
          if (batches.length) {
            const tQty  = batches.reduce((s, b) => s + (+b.quantity || 0), 0);
            const tProf = batches.reduce(
              (s, b) => s + ((+b.salePrice - +b.purchasePrice) * (+b.quantity || 0)),
              0
            );
            avgProfit = tQty ? tProf / tQty : 0;
          } else {
            avgProfit = (+p.retailPrice - +p.wholesalePrice);
          }

          ws.addRow({
            serial: idx + 1,
            productName   : p.productName,
            wholesalePrice: (+p.wholesalePrice).toFixed(2),
            retailPrice   : (+p.retailPrice).toFixed(2),
            quantity      : (+p.quantity).toFixed(2),
            unit          : p.unit || '',
            profitMargin  : (+p.profitMargin).toFixed(2),
            avgProfit     : avgProfit.toFixed(2),
            category      : p.category || ''
          });
        });

        /* 4. stream to client */
        res.setHeader(
          'Content-Type',
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        );
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="products_${Date.now()}.xlsx"`
        );

        await wb.xlsx.write(res);
        res.end();
      } catch (err) {
        res.status(500).send(err.toString());
      }
    }
  );

  return router;
};
